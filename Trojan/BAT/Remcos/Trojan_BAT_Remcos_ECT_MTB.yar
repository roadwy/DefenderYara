
rule Trojan_BAT_Remcos_ECT_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ECT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 44 58 6b 57 3c 5f 28 56 3f 63 71 4b 2e 6c 4a 3e 2d 2a 79 26 7a 76 39 70 72 66 38 62 69 59 43 46 65 4d 78 42 6d 36 5a 6e 47 33 48 34 4f 75 53 31 55 61 49 35 54 77 74 6f 41 23 52 73 21 2c 37 64 32 40 4c 5e 67 4e 68 6a 29 45 50 24 30 00 } //00 00 
	condition:
		any of ($a_*)
 
}