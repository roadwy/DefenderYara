
rule Trojan_Win32_Junkoil_A{
	meta:
		description = "Trojan:Win32/Junkoil.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {85 c0 74 31 68 90 01 02 40 00 6a 00 68 01 00 1f 00 e8 90 01 02 ff ff 85 c0 75 90 01 01 68 90 01 02 40 00 6a 00 68 66 66 66 66 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}