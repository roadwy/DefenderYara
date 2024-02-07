
rule Trojan_BAT_AsyncRat_NEAY_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {73 30 00 00 0a 0a 06 28 31 00 00 0a 03 50 6f 32 00 00 0a 6f 33 00 00 0a 0b 73 34 00 00 0a 0c 08 07 6f 35 00 00 0a 08 18 6f 36 00 00 0a 08 6f 37 00 00 0a 02 50 16 02 50 8e 69 6f 38 00 00 0a 2a } //05 00 
		$a_01_1 = {73 65 74 55 54 43 4d 69 6e 75 74 65 73 54 55 20 4a 75 72 61 73 73 69 63 2e 4c 69 62 72 61 72 79 2e 4a 53 46 75 6e 63 74 69 6f 6e 46 6c 61 67 73 } //00 00  setUTCMinutesTU Jurassic.Library.JSFunctionFlags
	condition:
		any of ($a_*)
 
}