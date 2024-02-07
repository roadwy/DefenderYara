
rule Trojan_BAT_Injuke_NEAC_MTB{
	meta:
		description = "Trojan:BAT/Injuke.NEAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 05 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 38 00 35 00 2e 00 32 00 30 00 39 00 2e 00 31 00 33 00 34 00 2e 00 38 00 36 00 } //04 00  http://85.209.134.86
		$a_01_1 = {2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 } //02 00  /c ping google.com
		$a_01_2 = {6e 65 77 76 65 72 73 69 6f 6e } //01 00  newversion
		$a_01_3 = {49 44 41 54 2d 52 38 } //01 00  IDAT-R8
		$a_01_4 = {53 79 73 74 65 6d 2e 57 69 6e 64 6f 77 73 2e 46 6f 72 6d 73 } //01 00  System.Windows.Forms
		$a_01_5 = {73 65 74 5f 57 69 6e 64 6f 77 53 74 79 6c 65 } //01 00  set_WindowStyle
		$a_01_6 = {50 72 6f 63 65 73 73 53 74 61 72 74 49 6e 66 6f } //00 00  ProcessStartInfo
	condition:
		any of ($a_*)
 
}