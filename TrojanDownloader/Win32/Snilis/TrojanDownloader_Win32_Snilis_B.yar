
rule TrojanDownloader_Win32_Snilis_B{
	meta:
		description = "TrojanDownloader:Win32/Snilis.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {39 00 63 00 56 00 33 00 76 00 39 00 70 00 38 00 4e 00 38 00 51 00 38 00 4c 00 39 00 79 00 63 00 41 00 34 00 4a 00 63 00 43 00 61 00 42 00 35 00 6d 00 62 00 43 00 64 00 51 00 38 00 41 00 39 00 56 00 64 00 42 00 61 00 42 00 64 00 56 00 62 00 } //01 00  9cV3v9p8N8Q8L9ycA4JcCaB5mbCdQ8A9VdBaBdVb
		$a_01_1 = {62 00 75 00 63 00 6b 00 73 00 } //00 00  bucks
	condition:
		any of ($a_*)
 
}