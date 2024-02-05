
rule Trojan_BAT_Gimmick_A{
	meta:
		description = "Trojan:BAT/Gimmick.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 00 57 00 6c 00 6a 00 63 00 6d 00 39 00 7a 00 62 00 32 00 5a 00 30 00 49 00 55 00 41 00 6a 00 4a 00 43 00 56 00 65 00 4a 00 69 00 6f 00 6f 00 4b 00 51 00 3d 00 3d 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}