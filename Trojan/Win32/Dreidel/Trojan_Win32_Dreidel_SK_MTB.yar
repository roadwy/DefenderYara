
rule Trojan_Win32_Dreidel_SK_MTB{
	meta:
		description = "Trojan:Win32/Dreidel.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {85 c9 7c 29 8b 35 40 90 40 00 b8 67 66 66 66 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 8d 14 80 03 d2 8b c1 2b c2 8a 90 3c 74 40 00 30 14 0e 41 3b 0d 4c 90 40 00 72 ca a1 40 90 40 00 50 e8 9f bb ff } //2
		$a_81_1 = {26 2a 79 67 75 66 64 6b 73 6a 66 73 64 61 } //2 &*ygufdksjfsda
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}