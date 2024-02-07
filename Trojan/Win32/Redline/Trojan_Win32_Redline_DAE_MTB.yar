
rule Trojan_Win32_Redline_DAE_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 03 00 "
		
	strings :
		$a_03_0 = {f6 17 80 2f 90 01 01 47 e2 90 00 } //01 00 
		$a_01_1 = {68 4d 45 69 37 75 34 48 69 70 5a 32 31 4d 6d 35 72 4f 47 6b 44 48 6d 57 55 36 77 67 52 7a 58 } //01 00  hMEi7u4HipZ21Mm5rOGkDHmWU6wgRzX
		$a_01_2 = {6e 42 70 71 47 55 43 72 6b 75 65 4b 55 32 49 7a 45 4b 4a 6d 6f 58 42 68 } //01 00  nBpqGUCrkueKU2IzEKJmoXBh
		$a_01_3 = {6b 74 6c 43 59 77 78 37 70 74 64 6d 36 31 50 78 4a 62 47 77 33 49 62 6b 67 4d 78 77 33 6e } //01 00  ktlCYwx7ptdm61PxJbGw3IbkgMxw3n
		$a_01_4 = {66 4a 36 35 4f 33 74 67 57 33 75 57 30 32 4d 6a 35 72 4c 4b 46 38 58 4b 75 65 } //01 00  fJ65O3tgW3uW02Mj5rLKF8XKue
		$a_01_5 = {42 54 30 6b 6e 54 38 6f 42 43 53 5a 42 52 68 53 65 72 46 4d 68 46 35 5a 34 47 52 6d 51 6a } //01 00  BT0knT8oBCSZBRhSerFMhF5Z4GRmQj
		$a_01_6 = {47 39 4a 61 39 52 6e 52 68 38 73 39 4b 51 57 61 48 52 68 46 45 75 67 62 77 65 57 63 66 } //00 00  G9Ja9RnRh8s9KQWaHRhFEugbweWcf
	condition:
		any of ($a_*)
 
}