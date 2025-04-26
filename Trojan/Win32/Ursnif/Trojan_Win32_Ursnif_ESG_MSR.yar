
rule Trojan_Win32_Ursnif_ESG_MSR{
	meta:
		description = "Trojan:Win32/Ursnif.ESG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 3a 5c 69 6e 5c 74 68 65 5c 74 6f 77 6e 5c 77 68 65 72 65 5c 61 68 75 6e 67 2e 70 64 62 } //1 d:\in\the\town\where\ahung.pdb
		$a_01_1 = {6d 00 6f 00 76 00 65 00 74 00 68 00 6d 00 65 00 61 00 74 00 6d 00 61 00 6e 00 66 00 69 00 66 00 74 00 68 00 79 00 69 00 65 00 6c 00 64 00 69 00 6e 00 67 00 6c 00 73 00 65 00 61 00 73 00 6f 00 6e 00 73 00 2e 00 56 00 61 00 69 00 72 00 } //1 movethmeatmanfifthyieldinglseasons.Vair
		$a_01_2 = {7a 6d 66 69 66 74 68 74 73 61 79 69 6e 67 2c 4b 43 61 74 74 6c 65 62 65 61 73 74 6d 6f 76 65 64 2e 42 } //1 zmfifthtsaying,KCattlebeastmoved.B
		$a_01_3 = {53 00 65 00 65 00 64 00 6c 00 61 00 6e 00 64 00 73 00 66 00 6f 00 72 00 57 00 66 00 61 00 63 00 65 00 76 00 6f 00 69 00 64 00 } //1 SeedlandsforWfacevoid
		$a_01_4 = {43 54 24 79 68 72 74 67 66 64 72 34 68 65 72 79 } //1 CT$yhrtgfdr4hery
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}