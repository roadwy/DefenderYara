
rule TrojanDownloader_Win32_Brinaskrem_A{
	meta:
		description = "TrojanDownloader:Win32/Brinaskrem.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 61 71 2a 2e 64 6c 6c } //01 00  uaq*.dll
		$a_01_1 = {25 63 25 63 25 63 25 63 25 63 2e 78 6d 70 } //01 00  %c%c%c%c%c.xmp
		$a_01_2 = {73 75 63 63 00 00 50 72 6f 78 79 } //02 00 
		$a_01_3 = {d3 d0 bf a8 b0 cd cb b9 bb f9 a3 ac b2 bb d2 aa b0 f3 b6 a8 73 68 65 6c 6c } //02 00 
		$a_01_4 = {75 0d 8b 6c 24 18 25 ff 0f 00 00 03 c7 01 28 8b 41 04 46 83 e8 08 83 c2 02 d1 e8 3b f0 72 } //00 00 
	condition:
		any of ($a_*)
 
}