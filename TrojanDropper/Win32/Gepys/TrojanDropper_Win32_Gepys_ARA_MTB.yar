
rule TrojanDropper_Win32_Gepys_ARA_MTB{
	meta:
		description = "TrojanDropper:Win32/Gepys.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 83 c0 01 89 45 f8 8b 4d f8 3b 4d 10 7d 39 8b 55 08 89 55 f4 8b 45 0c 89 45 e8 c7 45 fc 35 dc 07 00 c7 45 fc 35 dc 07 00 8b 4d e8 03 4d f8 0f b6 11 89 55 ec 8b 45 ec 89 45 f0 8b 4d f4 03 4d f8 8a 55 f0 88 11 eb b6 } //2
		$a_80_1 = {63 3a 5c 4d 6f 7a 69 6c 6c 61 5c 6a 62 76 75 73 72 6a 2e 65 78 65 } //c:\Mozilla\jbvusrj.exe  2
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}