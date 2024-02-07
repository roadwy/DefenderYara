
rule TrojanDownloader_Win32_Drstwex_F{
	meta:
		description = "TrojanDownloader:Win32/Drstwex.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 33 32 73 64 66 68 65 72 74 79 } //01 00  a32sdfherty
		$a_01_1 = {8b 00 8b d0 c1 e0 03 33 c2 05 bd 04 00 00 5a 89 02 c1 e8 18 } //01 00 
		$a_01_2 = {8a 1e 32 d8 88 1e eb df } //01 00 
		$a_01_3 = {8b 4d 0c 8b 55 08 e8 0b 00 00 00 30 02 42 e2 f6 } //00 00 
	condition:
		any of ($a_*)
 
}