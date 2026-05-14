
rule Trojan_MacOS_FakeWallet_A_MTB{
	meta:
		description = "Trojan:MacOS/FakeWallet.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {fc 6f be a9 fd 7b 01 a9 fd 43 00 91 ff c3 0b d1 e8 03 01 aa e1 03 02 aa a0 83 12 f8 a8 03 12 f8 a0 a3 03 d1 e0 ab 00 f9 08 00 80 d2 e8 af 00 f9 bf 83 11 f8 93 03 00 94 20 00 00 90 00 a0 00 91 28 00 00 90 08 0d 40 f9 00 01 3f d6 a8 c3 03 d1 e8 a7 00 f9 a0 03 11 f8 } //1
		$a_01_1 = {a8 e3 03 d1 e8 a3 00 f9 a0 83 10 f8 48 00 00 90 00 4d 44 f9 74 03 00 94 e1 77 40 f9 ce 03 00 94 a8 03 04 d1 e8 9f 00 f9 a0 03 10 f8 48 00 00 90 00 51 44 f9 6c 03 00 94 e1 77 40 f9 00 e4 00 2f e0 1b 00 fd a0 83 18 fc a0 03 18 fc 08 00 d1 d2 68 12 e8 f2 00 01 67 9e e0 3b 00 fd a0 83 17 fc 08 00 c7 d2 08 11 e8 f2 00 01 67 9e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}