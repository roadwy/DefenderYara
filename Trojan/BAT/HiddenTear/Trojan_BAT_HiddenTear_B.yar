
rule Trojan_BAT_HiddenTear_B{
	meta:
		description = "Trojan:BAT/HiddenTear.B,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {37 61 62 30 64 64 30 34 2d 34 33 65 30 2d 34 64 38 39 2d 62 65 35 39 2d 36 30 61 33 30 62 37 36 36 34 36 37 } //00 00 
	condition:
		any of ($a_*)
 
}