
rule Trojan_Linux_Mirai_DD{
	meta:
		description = "Trojan:Linux/Mirai.DD,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 04 00 00 04 00 "
		
	strings :
		$a_00_0 = {5b 73 63 61 6e 6e 65 72 5d 20 53 63 61 6e 6e 65 72 20 70 72 6f 63 65 73 73 20 69 6e 69 74 69 61 6c 69 7a 65 64 2e 20 53 63 61 6e 6e 69 6e 67 20 73 74 61 72 74 65 64 } //02 00  [scanner] Scanner process initialized. Scanning started
		$a_00_1 = {41 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 62 72 75 74 65 20 66 6f 75 6e 64 20 49 50 } //02 00  Attempting to brute found IP
		$a_00_2 = {5b 72 65 70 6f 72 74 5d 20 53 65 6e 64 20 73 63 61 6e 20 72 65 73 75 6c 74 20 74 6f 20 6c 6f 61 64 65 72 } //02 00  [report] Send scan result to loader
		$a_00_3 = {6c 6f 73 74 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 77 69 74 68 20 43 4e 43 } //00 00  lost connection with CNC
	condition:
		any of ($a_*)
 
}