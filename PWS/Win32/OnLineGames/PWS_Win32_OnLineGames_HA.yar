
rule PWS_Win32_OnLineGames_HA{
	meta:
		description = "PWS:Win32/OnLineGames.HA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {94 03 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 00 71 03 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 00 00 74 02 4f 70 65 6e 50 72 6f 63 65 73 73 00 } //1
		$a_00_1 = {3f 4e 61 6d 65 3d 25 73 26 70 61 73 73 77 6f 72 64 3d 25 73 26 5a 6f 6e 65 3d 25 73 26 53 65 72 76 65 72 3d 25 73 26 62 61 6e 6b 50 61 73 73 3d 25 73 26 4c 65 76 65 6c 3d 25 73 26 4d 42 3d 25 64 } //1 ?Name=%s&password=%s&Zone=%s&Server=%s&bankPass=%s&Level=%s&MB=%d
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}