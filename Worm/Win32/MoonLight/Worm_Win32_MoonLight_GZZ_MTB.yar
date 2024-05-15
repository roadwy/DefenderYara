
rule Worm_Win32_MoonLight_GZZ_MTB{
	meta:
		description = "Worm:Win32/MoonLight.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {21 13 31 df 47 90 01 02 5f 1b 69 46 25 90 01 04 30 5b 09 5e 22 c0 b4 5a e2 90 00 } //05 00 
		$a_01_1 = {33 0e 09 2a 0a d1 89 45 15 } //00 00 
	condition:
		any of ($a_*)
 
}