
rule Trojan_Win32_Snakeklg_GB_MTB{
	meta:
		description = "Trojan:Win32/Snakeklg.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 0a 00 "
		
	strings :
		$a_80_0 = {53 4e 41 4b 45 2d 4b 45 59 4c 4f 47 47 45 52 } //SNAKE-KEYLOGGER  01 00 
		$a_80_1 = {53 2d 2d 2d 2d 2d 2d 2d 2d 4e 2d 2d 2d 2d 2d 2d 2d 2d 41 2d 2d 2d 2d 2d 2d 2d 2d 4b 2d 2d 2d 2d 2d 2d 2d 2d 45 } //S--------N--------A--------K--------E  01 00 
		$a_02_2 = {4b 00 45 00 59 00 4c 00 4f 00 47 00 47 00 45 00 52 00 90 02 1e 53 00 90 02 19 4e 00 90 02 19 41 00 90 02 19 4b 00 90 02 19 45 00 90 00 } //01 00 
		$a_02_3 = {4b 45 59 4c 4f 47 47 45 52 90 02 1e 53 90 02 19 4e 90 02 19 41 90 02 19 4b 90 02 19 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}