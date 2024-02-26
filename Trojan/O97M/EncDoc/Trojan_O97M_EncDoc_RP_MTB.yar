
rule Trojan_O97M_EncDoc_RP_MTB{
	meta:
		description = "Trojan:O97M/EncDoc.RP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 65 67 73 76 72 33 32 2e 65 78 65 } //01 00  regsvr32.exe
		$a_01_1 = {53 79 73 57 6f 77 36 34 5c } //01 00  SysWow64\
		$a_01_2 = {5c 57 69 6e 64 6f 77 73 5c } //01 00  \Windows\
		$a_01_3 = {22 37 37 37 37 22 } //01 00  "7777"
		$a_01_4 = {52 45 54 55 52 4e } //00 00  RETURN
	condition:
		any of ($a_*)
 
}