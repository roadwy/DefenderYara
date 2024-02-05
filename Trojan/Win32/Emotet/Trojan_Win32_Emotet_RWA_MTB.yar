
rule Trojan_Win32_Emotet_RWA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {81 c7 00 10 00 00 0b c7 50 56 53 6a ff } //01 00 
		$a_80_1 = {51 6b 50 75 58 30 6e 36 21 54 26 67 4d 37 67 44 32 40 77 44 70 70 74 4f 4a 47 26 58 5f 4d 5f 49 42 26 3f 71 6b 29 62 26 39 53 71 32 29 7a 71 5a 50 4a 4b 68 36 63 61 24 63 4b 43 62 26 4e 2b } //QkPuX0n6!T&gM7gD2@wDpptOJG&X_M_IB&?qk)b&9Sq2)zqZPJKh6ca$cKCb&N+  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_RWA_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_80_0 = {78 4b 54 53 4e 23 5e 43 4b 45 6f 6a 3e 39 74 62 23 31 3c 2a 4d 57 54 73 76 36 33 34 6b 35 62 54 52 43 37 23 65 35 29 4e 6a 4f 58 75 36 46 43 66 77 6c 40 4a 42 4c 70 54 30 3e 56 4a 78 3c 79 50 55 73 41 30 4b 7a 4e 7a 45 6f 39 30 63 25 6b 54 26 47 34 41 23 4d 53 34 26 } //xKTSN#^CKEoj>9tb#1<*MWTsv634k5bTRC7#e5)NjOXu6FCfwl@JBLpT0>VJx<yPUsA0KzNzEo90c%kT&G4A#MS4&  01 00 
		$a_03_1 = {0d 00 10 00 00 90 02 05 8b 55 90 02 05 6a 00 6a ff ff 90 02 05 89 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}