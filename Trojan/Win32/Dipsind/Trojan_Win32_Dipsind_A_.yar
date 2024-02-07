
rule Trojan_Win32_Dipsind_A_{
	meta:
		description = "Trojan:Win32/Dipsind.A!!Dipsind.gen!dha,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 4f 50 53 48 30 33 53 4b 30 39 50 4f 4b 53 49 44 37 46 46 36 37 34 50 53 4c 49 39 31 39 36 35 } //05 00  AOPSH03SK09POKSID7FF674PSLI91965
	condition:
		any of ($a_*)
 
}