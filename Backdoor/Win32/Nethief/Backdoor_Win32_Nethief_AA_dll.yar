
rule Backdoor_Win32_Nethief_AA_dll{
	meta:
		description = "Backdoor:Win32/Nethief.AA!dll,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {69 69 70 43 6f 6e 6e 65 63 74 53 65 72 76 65 72 } //0a 00  iipConnectServer
		$a_00_1 = {49 49 50 43 6c 69 65 6e 74 2e 64 6c 6c } //0a 00  IIPClient.dll
		$a_00_2 = {69 69 70 49 6e 73 74 61 6c 6c 43 61 6c 6c 62 61 63 } //01 00  iipInstallCallbac
		$a_02_3 = {c7 46 04 01 00 00 00 89 08 8b 4c 24 18 89 50 04 8b 54 24 1c 89 48 08 8b 4c 24 20 89 50 0c 8b 44 24 24 8b 54 24 0c 50 51 52 ff 15 90 01 04 83 c4 10 90 00 } //01 00 
		$a_02_4 = {8b 4e 1c 8b 56 18 51 8b 4c 24 2c 52 8b 54 24 2c 51 8b 4c 24 2c 52 51 53 8b c8 e8 90 01 04 b8 01 00 00 00 8b 4c 24 0c 64 89 0d 00 00 00 00 5f 5e 5b 83 c4 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}