
rule Trojan_MacOS_Dropper_A{
	meta:
		description = "Trojan:MacOS/Dropper.A,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {47 6f 6c 64 65 6e 20 42 6f 6f 6b 31 } //01 00  Golden Book1
		$a_00_1 = {48 35 59 4c 35 36 36 38 43 37 31 } //02 00  H5YL5668C71
		$a_00_2 = {46 69 6e 64 65 72 46 6f 6e 74 73 55 70 64 61 74 65 72 2e 61 70 70 27 00 6b 69 6c 6c 61 6c 6c 20 54 65 72 6d 69 6e 61 6c } //02 00 
		$a_00_3 = {3c 73 74 72 69 6e 67 3e 69 54 75 6e 65 73 5f 74 72 75 73 68 3c 2f 73 74 72 69 6e 67 3e 0d 0a 09 3c 6b 65 79 3e 4f 6e 44 65 6d 61 6e 64 3c 2f 6b 65 79 3e } //01 00 
		$a_00_4 = {70 67 72 65 70 20 2d 66 20 73 61 66 61 72 69 66 6f 6e 74 73 61 67 65 6e 74 } //00 00  pgrep -f safarifontsagent
		$a_00_5 = {5d 04 00 } //00 f7 
	condition:
		any of ($a_*)
 
}