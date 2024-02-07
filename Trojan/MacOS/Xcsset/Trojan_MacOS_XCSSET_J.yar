
rule Trojan_MacOS_XCSSET_J{
	meta:
		description = "Trojan:MacOS/XCSSET.J,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 61 43 38 30 62 77 58 73 63 6a 71 5a 37 4b 4d 36 56 4f 78 55 4c 4f 42 35 33 34 } //01 00  HaC80bwXscjqZ7KM6VOxULOB534
		$a_01_1 = {4e 6f 20 77 72 69 74 61 62 6c 65 20 61 70 70 73 20 77 65 72 65 20 66 6f 75 6e 64 20 61 6e 64 20 6d 6f 64 64 65 64 2e 20 45 78 69 74 69 6e 67 2e } //01 00  No writable apps were found and modded. Exiting.
		$a_01_2 = {52 65 73 65 74 74 69 6e 67 20 61 6c 6c 20 63 6f 6f 6b 69 65 73 2c 20 70 61 79 6c 6f 61 64 73 2c 20 63 6f 72 73 20 74 61 72 67 65 74 73 } //01 00  Resetting all cookies, payloads, cors targets
		$a_01_3 = {43 53 50 20 42 79 70 61 73 73 20 64 69 73 61 62 6c 65 64 2e 20 45 6e 61 62 6c 69 6e 67 } //01 00  CSP Bypass disabled. Enabling
		$a_01_4 = {67 72 65 70 20 2d 71 20 27 72 65 6d 6f 74 65 2d 64 65 62 75 67 67 69 6e 67 2d 70 6f 72 74 3d } //00 00  grep -q 'remote-debugging-port=
	condition:
		any of ($a_*)
 
}