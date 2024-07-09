
rule Trojan_Win32_Emotetcrypt_FC_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.FC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 40 68 00 30 00 00 8b 4d d0 51 6a 00 6a ff ff 15 } //5
		$a_03_1 = {6a 40 ba 00 20 00 00 2b 15 ?? ?? ?? ?? 81 ca 00 10 00 00 52 8b 45 d0 50 6a 00 ff 15 } //5
		$a_81_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //5 DllRegisterServer
		$a_81_3 = {36 70 32 5a 36 61 36 43 5a 26 4d 3e 5a 52 24 61 40 59 24 78 6e 51 3f 3c 58 42 65 68 3c 32 32 6d 7a 26 30 } //1 6p2Z6a6CZ&M>ZR$a@Y$xnQ?<XBeh<22mz&0
		$a_81_4 = {6b 78 6e 59 5f 4c 3f 7a 71 6c 53 45 75 75 35 53 32 56 46 6f 6c 36 53 48 31 71 3f 38 36 58 5e 66 55 37 34 42 } //1 kxnY_L?zqlSEuu5S2VFol6SH1q?86X^fU74B
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_81_2  & 1)*5+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=16
 
}