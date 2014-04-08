using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace HDInsight.AsvKeyEncryptor
{
    internal class Program
    {
        private static String recipientName = "hdinortheuropemgmtcert";

        private static void Main(string[] args)
        {
            var showReverseCheck = false;
            
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: HDInsight.AsvKeyEncryptor rawkey optional(recipientName reverseCheck[bool])");
            }
            if (args.Length > 1)
            {
                recipientName = args[1];
            }
            if (args.Length > 2)
            {
                showReverseCheck = args[2].ToUpper() == bool.TrueString.ToUpper();
            }
            
            //  Original message.
            var msg = args[0];

            //  Convert message to an array of Unicode bytes for signing.
            UnicodeEncoding unicode = new UnicodeEncoding();
            byte[] msgBytes = unicode.GetBytes(msg);

            //  The recipient's certificate is necessary to encrypt
            //  the message for that recipient.
            X509Certificate2 recipientCert = GetRecipientCert();

            byte[] encodedEnvelopedCms = EncryptMsg(msgBytes,
                recipientCert);

            Console.Write(Convert.ToBase64String(encodedEnvelopedCms));
            Console.WriteLine();

            if (showReverseCheck)
            {
                Byte[] decryptedMsg = DecryptMsg(encodedEnvelopedCms);

                //  Convert Unicode bytes to the original message string.
                Console.WriteLine("\nDecrypted Message: {0}",
                    unicode.GetString(decryptedMsg));
            }
        }

        //  Open the AddressBook (also known as Other in 
        //  Internet Explorer) certificate store and search for 
        //  a recipient certificate with which to encrypt the 
        //  message. The certificate must have a subject name 
        //  of "Recipient1".
        public static X509Certificate2 GetRecipientCert()
        {
            //  Open the AddressBook local user X509 certificate store.
            X509Store storeAddressBook = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            storeAddressBook.Open(OpenFlags.ReadOnly);

            
            //  Get recipient certificate.
            //  For purposes of this sample, do not validate the
            //  certificate. Note that in a production environment,
            //  validating the certificate will probably be necessary.
            X509Certificate2Collection certColl = storeAddressBook.
                Certificates.Find(X509FindType.FindByIssuerName,
                    recipientName, false);

            storeAddressBook.Close();

            return certColl[0];
        }

        //  Encrypt the message with the public key of
        //  the recipient. This is done by enveloping the message by
        //  using an EnvelopedCms object.
        public static byte[] EncryptMsg(
            Byte[] msg,
            X509Certificate2 recipientCert)
        {
            //  Place the message in a ContentInfo object.
            //  This is required to build an EnvelopedCms object.
            ContentInfo contentInfo = new ContentInfo(msg);

            //  Instantiate an EnvelopedCms object with the ContentInfo
            //  above.
            //  Has default SubjectIdentifierType IssuerAndSerialNumber.
            //  Has default ContentEncryptionAlgorithm property value
            //  RSA_DES_EDE3_CBC.
            EnvelopedCms envelopedCms = new EnvelopedCms(contentInfo);

            //  Formulate a CmsRecipient object that
            //  represents information about the recipient 
            //  to encrypt the message for.
            CmsRecipient recip1 = new CmsRecipient(
                SubjectIdentifierType.IssuerAndSerialNumber,
                recipientCert);

            //  Encrypt the message for the recipient.
            envelopedCms.Encrypt(recip1);

            //  The encoded EnvelopedCms message contains the message
            //  ciphertext and the information about each recipient 
            //  that the message was enveloped for.
            return envelopedCms.Encode();
        }

        //  Decrypt the encoded EnvelopedCms message.
        public static Byte[] DecryptMsg(byte[] encodedEnvelopedCms)
        {
            //  Prepare object in which to decode and decrypt.
            EnvelopedCms envelopedCms = new EnvelopedCms();

            //  Decode the message.
            envelopedCms.Decode(encodedEnvelopedCms);

            //  Display the number of recipients the message is
            //  enveloped for; it should be 1 for this example.
            DisplayEnvelopedCms(envelopedCms, false);

            //  Decrypt the message for the single recipient.
            Console.Write("Decrypting Data ... ");
            envelopedCms.Decrypt(envelopedCms.RecipientInfos[0]);
            Console.WriteLine("Done.");

            //  The decrypted message occupies the ContentInfo property
            //  after the Decrypt method is invoked.
            return envelopedCms.ContentInfo.Content;
        }

        //  Display the ContentInfo property of an EnvelopedCms object.
        private static void DisplayEnvelopedCmsContent(String desc,
            EnvelopedCms envelopedCms)
        {
            Console.WriteLine(desc + " (length {0}):  ",
                envelopedCms.ContentInfo.Content.Length);
            foreach (byte b in envelopedCms.ContentInfo.Content)
            {
                Console.Write(b.ToString() + " ");
            }
            Console.WriteLine();
        }

        //  Display some properties of an EnvelopedCms object.
        private static void DisplayEnvelopedCms(EnvelopedCms e,
            Boolean displayContent)
        {
            Console.WriteLine("\nEnveloped CMS/PKCS #7 Message " +
                              "Information:");
            Console.WriteLine(
                "\tThe number of recipients for the Enveloped CMS/PKCS " +
                "#7 is: {0}", e.RecipientInfos.Count);
            for (int i = 0; i < e.RecipientInfos.Count; i++)
            {
                Console.WriteLine(
                    "\tRecipient #{0} has type {1}.",
                    i + 1,
                    e.RecipientInfos[i].RecipientIdentifier.Type);
            }
            if (displayContent)
            {
                DisplayEnvelopedCmsContent("Enveloped CMS/PKCS " +
                                           "#7 Content", e);
            }
            Console.WriteLine();
        }
    }
}
