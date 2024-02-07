
rule TrojanDownloader_Win32_Doina_D_MTB{
	meta:
		description = "TrojanDownloader:Win32/Doina.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {c6 84 24 51 02 00 00 72 88 9c 24 90 01 04 c6 84 24 90 01 04 61 c6 84 24 90 01 04 74 88 9c 24 90 01 04 c6 84 24 90 01 04 44 c6 84 24 90 01 04 69 c6 84 24 90 01 04 72 88 9c 24 90 01 04 c6 84 24 90 01 04 63 c6 84 24 90 01 04 74 c6 84 24 90 01 04 6f c6 84 24 90 01 04 72 c6 84 24 90 01 04 79 c6 84 24 90 00 } //01 00 
		$a_01_1 = {4b 69 6c 6c 54 69 6d 65 72 } //00 00  KillTimer
	condition:
		any of ($a_*)
 
}