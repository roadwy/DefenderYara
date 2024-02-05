
rule Trojan_Win32_Gozi_R_MTB{
	meta:
		description = "Trojan:Win32/Gozi.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 31 44 57 52 74 49 2e 64 6c 6c } //01 00 
		$a_01_1 = {35 62 32 32 64 31 62 32 63 32 37 64 61 33 63 39 61 } //01 00 
		$a_01_2 = {39 38 37 63 31 35 32 32 34 61 64 65 39 65 39 33 61 62 37 } //01 00 
		$a_01_3 = {61 38 33 31 35 30 62 63 37 36 31 34 34 64 38 35 39 } //00 00 
	condition:
		any of ($a_*)
 
}