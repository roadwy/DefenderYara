
rule Trojan_BAT_Perseus_ABM_MTB{
	meta:
		description = "Trojan:BAT/Perseus.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {6d 79 73 65 6c 66 2e 64 6c 6c } //myself.dll  3
		$a_80_1 = {42 65 65 66 2e 64 6c 6c } //Beef.dll  3
		$a_80_2 = {72 4f 6e 41 6c 44 6f } //rOnAlDo  3
		$a_80_3 = {43 6f 6e 74 61 69 6e 73 4b 65 79 } //ContainsKey  3
		$a_80_4 = {6d 61 6e 61 67 61 6d 65 6e 74 2e 69 6e 66 } //managament.inf  3
		$a_80_5 = {63 6f 73 74 75 72 61 2e 6d 61 6e 61 67 61 6d 65 6e 74 2e 69 6e 66 2e 64 6c 6c 2e 7a 69 70 } //costura.managament.inf.dll.zip  3
		$a_80_6 = {50 72 6f 63 65 73 73 65 64 42 79 46 6f 64 79 } //ProcessedByFody  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}