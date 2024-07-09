
rule Backdoor_Win32_Nethief_AA_dll{
	meta:
		description = "Backdoor:Win32/Nethief.AA!dll,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_00_0 = {69 69 70 43 6f 6e 6e 65 63 74 53 65 72 76 65 72 } //10 iipConnectServer
		$a_00_1 = {49 49 50 43 6c 69 65 6e 74 2e 64 6c 6c } //10 IIPClient.dll
		$a_00_2 = {69 69 70 49 6e 73 74 61 6c 6c 43 61 6c 6c 62 61 63 } //10 iipInstallCallbac
		$a_02_3 = {c7 46 04 01 00 00 00 89 08 8b 4c 24 18 89 50 04 8b 54 24 1c 89 48 08 8b 4c 24 20 89 50 0c 8b 44 24 24 8b 54 24 0c 50 51 52 ff 15 ?? ?? ?? ?? 83 c4 10 } //1
		$a_02_4 = {8b 4e 1c 8b 56 18 51 8b 4c 24 2c 52 8b 54 24 2c 51 8b 4c 24 2c 52 51 53 8b c8 e8 ?? ?? ?? ?? b8 01 00 00 00 8b 4c 24 0c 64 89 0d 00 00 00 00 5f 5e 5b 83 c4 0c } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1) >=31
 
}