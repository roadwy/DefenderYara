
rule Trojan_Linux_Moobot_B{
	meta:
		description = "Trojan:Linux/Moobot.B,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_00_0 = {2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 } //3 /x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A
		$a_00_1 = {53 65 6c 66 20 52 65 70 20 46 75 63 6b 69 6e 67 20 4e 65 54 69 53 20 61 6e 64 20 54 68 69 73 69 74 79 } //3 Self Rep Fucking NeTiS and Thisity
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*3) >=6
 
}