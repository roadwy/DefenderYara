
rule Trojan_Win32_Dridex_PO_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 18 8b 90 02 03 ba 90 02 04 f7 90 01 01 69 90 02 05 01 90 01 01 89 90 02 03 89 90 02 03 8b 90 02 03 83 90 02 02 89 90 02 03 8b 90 02 03 8b 90 02 02 8b 90 02 03 2b 90 02 03 89 90 02 03 80 90 02 03 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}