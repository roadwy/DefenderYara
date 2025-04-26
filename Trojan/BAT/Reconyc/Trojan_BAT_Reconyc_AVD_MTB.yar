
rule Trojan_BAT_Reconyc_AVD_MTB{
	meta:
		description = "Trojan:BAT/Reconyc.AVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 06 00 00 "
		
	strings :
		$a_00_0 = {06 6e 17 6a 58 20 ff 00 00 00 6a 5f 6d 0a 11 07 11 04 06 95 58 6e 20 ff 00 00 00 6a 5f 6d 13 07 11 04 06 95 13 05 11 04 06 11 04 11 07 95 9e 11 04 11 07 11 05 9e 11 08 09 02 09 91 11 04 11 04 06 95 11 04 11 07 95 58 6e 20 ff 00 00 00 6a 5f 69 95 61 d2 9c 09 17 58 0d } //10
		$a_80_1 = {52 65 61 64 41 6c 6c 54 65 78 74 } //ReadAllText  5
		$a_80_2 = {73 63 69 77 79 73 6b 61 76 65 6f 6c 61 74 73 61 77 75 6e 65 74 61 67 62 73 66 71 69 66 } //sciwyskaveolatsawunetagbsfqif  5
		$a_80_3 = {67 65 74 5f 4d 61 69 6e 4d 6f 64 75 6c 65 } //get_MainModule  5
		$a_80_4 = {67 65 74 5f 46 69 6c 65 4e 61 6d 65 } //get_FileName  5
		$a_80_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  5
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_80_3  & 1)*5+(#a_80_4  & 1)*5+(#a_80_5  & 1)*5) >=35
 
}