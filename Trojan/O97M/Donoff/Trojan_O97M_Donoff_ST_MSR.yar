
rule Trojan_O97M_Donoff_ST_MSR{
	meta:
		description = "Trojan:O97M/Donoff.ST!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 72 4b 6f 6e 65 72 74 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 } //1 FrKonert = Application.StartupPath
		$a_01_1 = {54 69 52 66 6f 6c 20 3d 20 46 72 4b 6f 6e 65 72 74 20 26 20 22 5c 22 20 26 20 4d 65 2e 4e 61 6d 65 20 26 20 46 69 4b 65 72 76 68 20 26 20 22 2e 74 78 74 74 78 74 74 78 74 2e 22 } //1 TiRfol = FrKonert & "\" & Me.Name & FiKervh & ".txttxttxt."
		$a_01_2 = {54 69 52 66 6f 6c 20 3d 20 46 69 4e 65 72 74 79 28 22 65 78 20 61 70 6c 6f 20 61 72 65 20 61 72 2e 65 20 61 78 20 61 65 20 22 29 } //1 TiRfol = FiNerty("ex aplo are ar.e ax ae ")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}