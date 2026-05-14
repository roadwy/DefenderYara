
rule Trojan_Win32_Goptaju_G{
	meta:
		description = "Trojan:Win32/Goptaju.G,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_00_0 = {69 00 65 00 78 00 28 00 24 00 90 00 02 00 08 00 2b 00 24 00 90 00 02 00 08 00 2b 00 24 00 90 00 02 00 08 00 68 00 74 00 74 00 70 00 } //10
	condition:
		((#a_00_0  & 1)*10) >=10
 
}