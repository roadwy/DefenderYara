
rule Trojan_Win32_Raspberryrobin_RA_MTB{
	meta:
		description = "Trojan:Win32/Raspberryrobin.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 6e 69 75 62 79 47 74 72 72 72 72 63 72 } //01 00 
		$a_01_1 = {50 6f 69 69 6e 46 78 72 63 74 } //01 00 
		$a_01_2 = {4c 6e 66 75 68 54 76 74 63 72 } //00 00 
	condition:
		any of ($a_*)
 
}