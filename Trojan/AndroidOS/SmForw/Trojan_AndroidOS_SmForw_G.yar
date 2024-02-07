
rule Trojan_AndroidOS_SmForw_G{
	meta:
		description = "Trojan:AndroidOS/SmForw.G,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {79 59 6c 6c 6f 49 45 6f 72 74 68 6f 70 65 64 69 63 38 39 39 74 } //02 00  yYlloIEorthopedic899t
		$a_01_1 = {76 50 72 65 69 4e 4b 61 70 61 74 68 65 74 69 63 38 30 33 69 } //02 00  vPreiNKapathetic803i
		$a_01_2 = {67 5a 7a 6f 75 48 51 70 6e 65 75 6d 6f 6e 69 61 37 39 37 68 } //00 00  gZzouHQpneumonia797h
	condition:
		any of ($a_*)
 
}