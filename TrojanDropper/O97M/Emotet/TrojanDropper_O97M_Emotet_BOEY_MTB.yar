
rule TrojanDropper_O97M_Emotet_BOEY_MTB{
	meta:
		description = "TrojanDropper:O97M/Emotet.BOEY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 74 65 72 72 61 73 73 61 2d 63 61 66 65 2e 63 6f 6d 2f 39 79 6a 78 6e 65 73 2f 31 38 70 32 53 37 62 42 72 64 70 4d 36 46 72 41 63 2f } //1 ://terrassa-cafe.com/9yjxnes/18p2S7bBrdpM6FrAc/
		$a_01_1 = {3a 2f 2f 6d 6f 73 65 6c 65 74 72 6f 6e 69 63 6f 73 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 35 2f } //1 ://moseletronicos.com/wp-content/5/
		$a_01_2 = {3a 2f 2f 73 61 62 61 69 74 68 61 69 6d 61 73 73 20 61 67 65 2e 63 6f 6d 2e 61 75 2f 77 70 2d 61 64 6d 69 6e 2f 48 67 62 6e 33 65 2f } //1 ://sabaithaimass age.com.au/wp-admin/Hgbn3e/
		$a_01_3 = {3a 2f 2f 77 69 72 65 6d 61 78 2e 61 76 61 73 70 61 64 61 6e 2e 63 6f 6d 2f 61 64 6d 69 6e 2f 49 74 6f 70 69 62 49 5a 46 33 64 78 70 79 30 2f } //1 ://wiremax.avaspadan.com/admin/ItopibIZF3dxpy0/
		$a_01_4 = {3a 2f 2f 74 72 6f 6f 70 73 69 74 65 73 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 43 7a 4d 4a 6d 32 76 66 62 41 34 6f 73 53 48 48 2f } //1 ://troopsites.com/wp-admin/CzMJm2vfbA4osSHH/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}