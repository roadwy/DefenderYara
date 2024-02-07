
rule Worm_Win32_Opanki_CW{
	meta:
		description = "Worm:Win32/Opanki.CW,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 49 4d 5f 49 4d 65 73 73 61 67 65 } //01 00  AIM_IMessage
		$a_00_1 = {5f 4f 73 63 61 72 5f 54 72 65 65 } //01 00  _Oscar_Tree
		$a_00_2 = {5f 4f 73 63 61 72 5f 53 74 61 74 75 73 4e 6f 74 69 66 79 } //01 00  _Oscar_StatusNotify
		$a_00_3 = {5f 41 69 6d 41 64 } //01 00  _AimAd
		$a_00_4 = {57 6e 64 41 74 65 33 32 43 6c 61 73 73 } //01 00  WndAte32Class
		$a_02_5 = {57 6a 00 68 90 01 04 ff 15 90 01 04 8b 3d 90 01 04 8b f0 56 ff d7 85 c0 74 90 01 01 6a 00 68 23 4e 00 00 68 11 01 00 00 56 ff 15 90 01 04 8b 1d 90 01 04 33 f6 90 00 } //01 00 
		$a_02_6 = {52 ff d7 8b f0 56 ff d3 85 c0 74 90 01 01 56 ff 15 90 01 04 3d 99 01 00 00 75 90 01 01 6a 00 6a 00 68 01 02 00 00 56 ff d5 6a 00 6a 00 68 02 02 00 00 56 ff d5 33 f6 56 ff d3 85 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}