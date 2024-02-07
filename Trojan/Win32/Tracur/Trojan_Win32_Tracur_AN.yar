
rule Trojan_Win32_Tracur_AN{
	meta:
		description = "Trojan:Win32/Tracur.AN,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {22 6d 61 74 63 68 65 73 22 3a 20 5b 20 22 68 74 74 70 3a 2f 2f 2a 2f 2a 22 2c 20 22 68 74 74 70 73 3a 2f 2f 2a 2f 2a 22 20 5d 2c } //01 00  "matches": [ "http://*/*", "https://*/*" ],
		$a_01_1 = {28 2f 5c 2e 62 69 6e 67 5c 2e 5b 61 2d 7a 5d 7b 32 2c 34 7d } //01 00  (/\.bing\.[a-z]{2,4}
		$a_01_2 = {5c 78 36 42 5c 78 36 35 5c 78 37 39 5c 78 32 30 5c 78 33 41 22 2c 22 5c 78 32 30 5c 78 37 33 5c 78 36 31 5c 78 36 43 5c 78 37 34 5c 78 33 41 } //02 00  \x6B\x65\x79\x20\x3A","\x20\x73\x61\x6C\x74\x3A
		$a_00_3 = {8b 72 28 6a 18 59 31 ff 31 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 49 } //00 00 
	condition:
		any of ($a_*)
 
}