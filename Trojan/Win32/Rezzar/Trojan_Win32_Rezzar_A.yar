
rule Trojan_Win32_Rezzar_A{
	meta:
		description = "Trojan:Win32/Rezzar.A,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}