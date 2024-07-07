
rule Trojan_MacOS_SamScissors_A{
	meta:
		description = "Trojan:MacOS/SamScissors.A,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 70 64 61 74 65 41 67 65 6e 74 } //1 UpdateAgent
		$a_01_1 = {2e 6d 61 69 6e 5f 73 74 6f 72 61 67 65 } //1 .main_storage
		$a_01_2 = {55 4f 54 4a 5a 52 2d 13 14 1e 15 0d 09 5a 34 2e 5a 4b 4a 54 4a 41 5a 2d 13 14 4c 4e 41 5a 02 4c 4e 53 5a 3b 0a 0a 16 1f 2d 1f 18 31 13 0e 55 4f 49 4d 54 49 4c 5a 52 31 32 2e 37 36 56 5a 16 13 11 1f 5a 3d 1f 19 11 15 53 5a 39 12 08 15 17 1f 55 4b 4a 42 54 4a 54 4f 49 4f 43 54 4b 48 42 5a 29 1b 1c 1b 08 13 55 4f 49 4d 54 49 4c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}