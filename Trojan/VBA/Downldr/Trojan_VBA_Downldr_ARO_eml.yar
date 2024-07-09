
rule Trojan_VBA_Downldr_ARO_eml{
	meta:
		description = "Trojan:VBA/Downldr.ARO!eml,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 42 41 2e 47 65 74 4f 62 6a 65 63 74 [0-01] 28 [0-2f] 29 } //1
		$a_03_1 = {20 2b 20 49 49 66 28 28 [0-03] 20 2b 20 [0-03] 29 20 3d 20 [0-03] 2c 20 22 [0-05] 22 2c 20 22 [0-0a] 22 29 } //5
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*5) >=6
 
}