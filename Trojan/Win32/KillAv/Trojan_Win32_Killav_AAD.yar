
rule Trojan_Win32_Killav_AAD{
	meta:
		description = "Trojan:Win32/Killav.AAD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 0b 83 c3 04 8b 32 83 c2 04 f3 a4 48 75 f1 } //1
		$a_01_1 = {2e 74 6d 70 00 53 75 70 65 72 2d 45 43 00 } //1 琮灭匀灵牥䔭C
		$a_00_2 = {54 41 53 4b 4b 49 4c 4c 20 2f 46 20 2f 49 4d 20 4e 61 76 65 72 41 67 65 6e 74 2e 65 78 65 20 2f 54 } //1 TASKKILL /F /IM NaverAgent.exe /T
		$a_00_3 = {54 41 53 4b 4b 49 4c 4c 20 2f 46 20 2f 49 4d 20 6e 73 76 6d 6f 6e 2e 6e 70 63 20 2f 54 } //1 TASKKILL /F /IM nsvmon.npc /T
		$a_00_4 = {5c 72 65 73 74 61 72 74 2e 62 61 74 } //1 \restart.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}