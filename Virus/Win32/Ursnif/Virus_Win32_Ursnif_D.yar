
rule Virus_Win32_Ursnif_D{
	meta:
		description = "Virus:Win32/Ursnif.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b c7 89 47 10 8b 45 ec 50 8b d6 8d 4b 18 89 47 14 e8 10 01 00 00 8b 4d fc 8b 7d f8 8b 41 78 57 8b 4c 38 10 8b 44 38 1c c1 e1 02 2b c1 8b 44 38 04 03 c7 ff d0 68 00 80 00 00 6a 00 57 ff 15 } //1
		$a_01_1 = {8b fa 8b df c1 eb 02 83 e7 03 8b f1 85 db 74 1d 8a 45 0c 8b 16 02 c3 0f b6 c8 8b 45 08 d3 ca 33 d0 2b d3 89 16 83 c6 04 4b 75 e5 eb 03 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}