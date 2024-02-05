
rule PWS_Win32_Frethog_MS{
	meta:
		description = "PWS:Win32/Frethog.MS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 03 c1 80 30 86 41 3b cf 72 } //01 00 
		$a_01_1 = {80 38 e9 74 11 6a 05 } //01 00 
		$a_01_2 = {46 6f 72 74 68 67 6f 65 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}