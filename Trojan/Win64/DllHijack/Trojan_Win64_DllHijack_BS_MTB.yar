
rule Trojan_Win64_DllHijack_BS_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {31 c3 0f b6 45 f8 ba 0e 00 00 00 89 c1 e8 ?? ?? ff ff 31 d8 48 8b 4d 20 8b 55 fc 48 63 d2 88 44 91 03 83 45 fc 01 83 7d fc 03 0f 8e } //2
		$a_01_1 = {0f b6 45 ff 48 8b 55 10 48 01 d0 44 0f b6 00 0f b6 45 ff 48 8b 55 18 48 01 d0 0f b6 08 0f b6 45 ff 48 8b 55 10 48 01 c2 44 89 c0 31 c8 88 02 80 45 ff 01 80 7d ff 0f 76 } //2
		$a_01_2 = {50 72 69 6e 74 55 49 45 6e 74 72 79 57 } //1 PrintUIEntryW
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}