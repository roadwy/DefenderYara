
rule Trojan_BAT_Disstl_C_MTB{
	meta:
		description = "Trojan:BAT/Disstl.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 44 69 73 63 6f 72 64 } //\AppData\Roaming\Discord  3
		$a_80_1 = {79 74 70 6d 45 } //ytpmE  3
		$a_80_2 = {73 73 65 72 64 64 61 70 69 79 6d 73 69 74 61 68 77 } //sserddapiymsitahw  3
		$a_80_3 = {65 6e 6f 79 72 65 76 65 } //enoyreve  3
		$a_80_4 = {61 76 61 74 61 72 5f 75 72 6c } //avatar_url  3
		$a_80_5 = {53 65 6e 64 4d 65 52 65 73 75 6c 74 73 } //SendMeResults  3
		$a_80_6 = {64 72 6f 63 73 69 64 } //drocsid  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}