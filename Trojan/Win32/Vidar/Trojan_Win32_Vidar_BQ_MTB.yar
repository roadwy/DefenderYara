
rule Trojan_Win32_Vidar_BQ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 d2 f7 f1 8b 45 0c 8b 4d f4 53 6a 00 8a 04 02 32 04 31 88 06 } //00 00 
	condition:
		any of ($a_*)
 
}