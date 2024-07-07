
rule Trojan_Win32_Emotetcrypt_GO_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b d1 8b 4d 90 01 01 0f b6 14 11 8b 4d 90 01 01 0f b6 04 01 33 c2 8b 0d 90 01 04 0f af 0d 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 0f af 15 90 01 04 8b 35 90 01 04 0f af 35 90 01 04 8b 3d 90 01 04 0f af 3d 90 01 04 0f af 3d 90 01 04 8b 5d 90 01 01 03 1d 90 01 04 2b 1d 90 01 04 2b df 90 00 } //1
		$a_81_1 = {78 4b 54 53 4e 23 5e 43 4b 45 6f 6a 3e 39 74 62 23 31 3c 2a 4d 57 54 73 76 36 33 34 6b 35 62 54 52 43 37 23 65 35 29 4e 6a 4f 58 75 36 46 43 66 77 6c 40 4a 42 4c 70 54 30 3e 56 4a 78 3c 79 50 55 73 41 30 4b 7a 4e 7a 45 6f 39 30 63 25 6b 54 26 47 34 41 23 4d 53 34 26 } //1 xKTSN#^CKEoj>9tb#1<*MWTsv634k5bTRC7#e5)NjOXu6FCfwl@JBLpT0>VJx<yPUsA0KzNzEo90c%kT&G4A#MS4&
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}