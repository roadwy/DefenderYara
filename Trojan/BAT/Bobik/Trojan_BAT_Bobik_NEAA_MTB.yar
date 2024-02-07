
rule Trojan_BAT_Bobik_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Bobik.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 07 00 "
		
	strings :
		$a_01_0 = {65 31 34 39 37 65 33 63 2d 36 65 34 35 2d 34 36 36 65 2d 38 33 66 37 2d 62 62 66 66 34 62 35 33 34 63 37 61 } //05 00  e1497e3c-6e45-466e-83f7-bbff4b534c7a
		$a_01_1 = {61 00 73 00 70 00 6e 00 65 00 74 00 5f 00 77 00 70 00 2e 00 65 00 78 00 65 00 } //02 00  aspnet_wp.exe
		$a_01_2 = {41 75 74 6f 49 74 20 76 33 20 41 63 74 69 76 65 58 20 43 6f 6e 74 72 6f 6c } //02 00  AutoIt v3 ActiveX Control
		$a_01_3 = {50 6f 77 65 72 65 64 20 62 79 20 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 20 37 2e 32 2e 30 2e 32 37 38 39 } //02 00  Powered by SmartAssembly 7.2.0.2789
		$a_01_4 = {4a 6f 6e 61 74 68 61 6e 20 42 65 6e 6e 65 74 74 20 26 20 41 75 74 6f 49 74 20 54 65 61 6d } //00 00  Jonathan Bennett & AutoIt Team
	condition:
		any of ($a_*)
 
}