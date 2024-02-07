
rule Trojan_Win64_Emotet_MIA_MTB{
	meta:
		description = "Trojan:Win64/Emotet.MIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {78 79 75 7a } //01 00  xyuz
		$a_81_1 = {53 43 2e 45 58 45 } //01 00  SC.EXE
		$a_81_2 = {79 61 68 61 76 53 6f 64 75 6b 75 2e 74 78 74 } //01 00  yahavSoduku.txt
		$a_81_3 = {42 6f 61 72 64 20 6e 75 6d 62 65 72 3a } //01 00  Board number:
		$a_81_4 = {44 6c 6c 31 2e 64 6c 6c } //01 00  Dll1.dll
		$a_81_5 = {75 2e 74 78 74 } //01 00  u.txt
		$a_81_6 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00  DllRegisterServer
	condition:
		any of ($a_*)
 
}