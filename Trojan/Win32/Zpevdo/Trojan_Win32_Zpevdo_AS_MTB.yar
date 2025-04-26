
rule Trojan_Win32_Zpevdo_AS_MTB{
	meta:
		description = "Trojan:Win32/Zpevdo.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {8b 44 24 08 8b 4c 24 10 0b c8 8b 4c 24 0c 75 09 8b 44 24 04 f7 e1 c2 10 00 53 f7 e1 8b d8 8b 44 } //10
		$a_80_1 = {52 69 63 68 2e 70 64 62 } //Rich.pdb  3
		$a_80_2 = {53 74 65 61 6d 74 68 61 6e 6b } //Steamthank  3
		$a_80_3 = {55 73 65 73 74 61 79 } //Usestay  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3) >=19
 
}