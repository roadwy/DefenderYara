
rule Ransom_Win32_Basta_AA_MTB{
	meta:
		description = "Ransom:Win32/Basta.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {2b c1 8b 4d 90 01 01 8a 44 08 90 01 01 32 46 90 01 01 8b 4d 90 01 01 89 55 90 01 01 88 41 90 01 01 8b ca 8b 47 90 01 01 40 0f af 07 c1 e0 90 01 01 3b d8 0f 8c 90 00 } //01 00 
		$a_01_1 = {6e 65 74 77 6f 72 6b 65 78 70 6c 6f 72 65 72 2e 44 4c 4c } //01 00  networkexplorer.DLL
		$a_01_2 = {4e 6c 73 44 61 74 61 30 30 30 30 2e 44 4c 4c } //01 00  NlsData0000.DLL
		$a_01_3 = {4e 65 74 50 72 6f 6a 57 2e 44 4c 4c } //01 00  NetProjW.DLL
		$a_01_4 = {47 68 6f 66 72 2e 44 4c 4c } //01 00  Ghofr.DLL
		$a_01_5 = {66 67 31 32 32 2e 44 4c 4c } //00 00  fg122.DLL
	condition:
		any of ($a_*)
 
}