
rule Trojan_Win64_Lazy_MK_MTB{
	meta:
		description = "Trojan:Win64/Lazy.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 ba 00 10 00 00 81 e1 ff 0f 00 00 2b d1 48 8b 4f 10 3b d6 0f 4c f2 48 83 64 24 48 00 80 7f 20 00 4c 63 c6 } //35
	condition:
		((#a_01_0  & 1)*35) >=35
 
}
rule Trojan_Win64_Lazy_MK_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 38 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? 48 01 c8 48 89 44 24 40 c7 44 24 30 be 18 } //5
		$a_01_1 = {48 8b 45 d0 48 8b 0d 20 0c 02 00 48 89 08 48 8b 0d 1e 0c 02 00 48 89 48 08 66 8b 0d 1b 0c 02 00 66 89 48 10 8a 0d 13 0c 02 00 88 48 12 } //10
		$a_01_2 = {44 3a 5c 57 69 6e 43 6f 72 65 42 61 73 65 2e 70 64 62 } //20 D:\WinCoreBase.pdb
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*10+(#a_01_2  & 1)*20) >=35
 
}