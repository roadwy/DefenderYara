
rule Trojan_Win32_Korplug_RKA_MTB{
	meta:
		description = "Trojan:Win32/Korplug.RKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 34 35 36 37 38 39 31 32 33 34 35 36 37 38 39 31 32 33 34 35 36 37 38 39 31 32 33 34 35 36 37 38 39 31 32 33 34 35 36 37 38 39 31 32 33 34 35 36 37 38 39 31 32 33 34 35 36 37 38 39 31 32 33 34 35 36 37 38 } //01 00 
		$a_01_1 = {53 43 52 44 4c 4c } //01 00 
		$a_01_2 = {53 52 43 44 41 54 } //00 00 
	condition:
		any of ($a_*)
 
}