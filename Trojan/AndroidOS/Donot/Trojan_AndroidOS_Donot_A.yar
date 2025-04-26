
rule Trojan_AndroidOS_Donot_A{
	meta:
		description = "Trojan:AndroidOS/Donot.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {57 61 70 70 48 6f 6c 64 65 72 2e 74 78 74 } //1 WappHolder.txt
		$a_00_1 = {74 68 69 72 74 65 65 6e 3a 20 6c 6f 63 61 74 69 6f 6e 20 67 70 73 } //1 thirteen: location gps
		$a_00_2 = {73 65 74 6e 65 77 61 6c 72 61 6d } //1 setnewalram
		$a_01_3 = {44 42 5f 50 41 54 48 45 4e 54 45 52 } //1 DB_PATHENTER
		$a_00_4 = {73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 61 70 70 4d 61 70 20 77 68 65 72 65 20 4d 61 70 3d } //1 select * from WappMap where Map=
		$a_00_5 = {2e 61 6d 72 3a 3a 41 64 64 65 64 } //1 .amr::Added
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}