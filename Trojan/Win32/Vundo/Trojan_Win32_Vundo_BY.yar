
rule Trojan_Win32_Vundo_BY{
	meta:
		description = "Trojan:Win32/Vundo.BY,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {fa 8f 80 bf b1 50 67 73 43 44 54 ca 6d af 50 c0 5f 49 6e 73 74 6d 61 c6 46 d9 68 4e 10 1c 44 4c } //00 00 
	condition:
		any of ($a_*)
 
}