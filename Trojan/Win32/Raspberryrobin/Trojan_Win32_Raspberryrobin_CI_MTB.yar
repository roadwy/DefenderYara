
rule Trojan_Win32_Raspberryrobin_CI_MTB{
	meta:
		description = "Trojan:Win32/Raspberryrobin.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {44 74 72 63 79 74 76 4a 69 6e 6d } //02 00 
		$a_01_1 = {45 65 78 72 63 74 44 72 63 74 76 79 } //02 00 
		$a_01_2 = {44 78 65 72 63 74 53 78 72 63 74 76 79 } //00 00 
	condition:
		any of ($a_*)
 
}