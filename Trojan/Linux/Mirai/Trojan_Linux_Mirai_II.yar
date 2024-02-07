
rule Trojan_Linux_Mirai_II{
	meta:
		description = "Trojan:Linux/Mirai.II,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 } //02 00  /x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93
		$a_00_1 = {2f 72 6f 6f 74 2f 23 66 75 63 6b 77 68 69 74 65 68 61 74 73 } //02 00  /root/#fuckwhitehats
		$a_00_2 = {67 61 79 20 66 61 67 20 77 68 69 74 65 20 68 61 74 73 } //02 00  gay fag white hats
		$a_00_3 = {42 69 6e 64 65 64 20 61 6e 64 20 6c 69 73 74 65 6e 69 6e 67 20 6f 6e 20 61 64 64 72 65 73 73 } //00 00  Binded and listening on address
	condition:
		any of ($a_*)
 
}