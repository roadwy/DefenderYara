
rule TrojanDownloader_Win32_Carberp_S{
	meta:
		description = "TrojanDownloader:Win32/Carberp.S,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 65 f8 10 81 e1 80 00 00 00 89 75 fc 8b f2 81 e2 80 80 00 00 c1 e1 08 0b ca 8b 55 fc c1 ea 07 c1 e1 09 8d 1c 3f } //01 00 
		$a_01_1 = {73 26 73 74 61 74 70 61 73 73 3d 25 73 } //01 00 
		$a_01_2 = {2e 61 70 61 72 74 6d 73 6b 2e 72 75 } //01 00 
		$a_01_3 = {2e 72 75 70 6f 72 6e 6f 2e 74 76 } //00 00 
	condition:
		any of ($a_*)
 
}