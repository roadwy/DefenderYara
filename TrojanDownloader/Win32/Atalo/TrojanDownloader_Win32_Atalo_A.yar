
rule TrojanDownloader_Win32_Atalo_A{
	meta:
		description = "TrojanDownloader:Win32/Atalo.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {5b 41 52 51 55 49 56 4f 20 4f 4b 5d ?? ?? 50 52 49 4e 43 3d [0-42] 53 45 43 3d [0-42] 44 4c 4c 3d [0-42] 41 56 56 3d [0-42] 4d 53 4e 3d [0-42] 50 4c 55 47 3d } //1
		$a_01_1 = {49 66 20 65 78 69 73 74 20 22 25 73 22 20 47 6f 74 6f 20 31 } //1 If exist "%s" Goto 1
		$a_01_2 = {61 60 53 61 5e 52 5f 58 00 00 00 00 } //1
		$a_01_3 = {7e 28 bb 01 00 00 00 8d 45 f0 8b 55 fc 0f b6 54 1a ff 2b d3 2b d7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}