
rule Trojan_Win32_Azorult_ER_MTB{
	meta:
		description = "Trojan:Win32/Azorult.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 73 67 6f 2e 65 78 65 } //01 00  csgo.exe
		$a_01_1 = {63 6c 69 65 6e 74 2e 64 6c 6c } //01 00  client.dll
		$a_01_2 = {63 68 65 61 74 2d 6d 65 6e 75 2e 70 64 62 } //01 00  cheat-menu.pdb
		$a_01_3 = {67 52 55 2e 6f 30 58 47 48 } //01 00  gRU.o0XGH
		$a_81_4 = {5a 49 5f 6b 53 26 61 69 } //00 00  ZI_kS&ai
	condition:
		any of ($a_*)
 
}