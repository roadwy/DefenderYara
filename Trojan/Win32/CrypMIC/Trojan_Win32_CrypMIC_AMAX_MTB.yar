
rule Trojan_Win32_CrypMIC_AMAX_MTB{
	meta:
		description = "Trojan:Win32/CrypMIC.AMAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 74 68 65 20 70 75 62 6c 69 63 20 6b 65 79 2c 20 77 68 69 63 68 20 68 61 73 20 62 65 65 6e 20 74 72 61 6e 73 66 65 72 72 65 64 20 74 6f 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 76 69 61 20 74 68 65 20 49 6e 74 65 72 6e 65 74 2e } //2 ALL YOUR FILES were encrypted with the public key, which has been transferred to your computer via the Internet.
		$a_01_1 = {44 65 63 72 79 70 74 69 6e 67 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 69 73 20 6f 6e 6c 79 20 70 6f 73 73 69 62 6c 65 20 77 69 74 68 20 74 68 65 20 68 65 6c 70 20 6f 66 20 74 68 65 20 70 72 69 76 61 74 65 20 6b 65 79 20 61 6e 64 20 64 65 63 72 79 70 74 20 70 72 6f 67 72 61 6d 20 2c 20 77 68 69 63 68 20 69 73 20 6f 6e 20 6f 75 72 20 53 65 63 72 65 74 20 53 65 72 76 65 72 } //1 Decrypting of your files is only possible with the help of the private key and decrypt program , which is on our Secret Server
		$a_01_2 = {49 66 20 59 6f 75 20 68 61 76 65 20 72 65 61 6c 6c 79 20 76 61 6c 75 61 62 6c 65 20 5f 44 41 54 41 5f 2c 20 79 6f 75 20 62 65 74 74 65 72 20 5f 4e 4f 54 5f 20 5f 57 41 53 54 45 5f 20 5f 59 4f 55 52 5f 20 5f 54 49 4d 45 5f 2c 20 62 65 63 61 75 73 65 20 74 68 65 72 65 20 69 73 20 5f 4e 4f 5f 20 6f 74 68 65 72 20 77 61 79 20 74 6f 20 67 65 74 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 65 78 63 65 70 74 20 6d 61 6b 65 20 61 20 5f 50 41 59 4d 45 4e 54 5f } //1 If You have really valuable _DATA_, you better _NOT_ _WASTE_ _YOUR_ _TIME_, because there is _NO_ other way to get your files, except make a _PAYMENT_
		$a_80_3 = {3a 5c 54 45 4d 50 5c 52 45 41 44 4d 45 2e 54 58 54 } //:\TEMP\README.TXT  1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}