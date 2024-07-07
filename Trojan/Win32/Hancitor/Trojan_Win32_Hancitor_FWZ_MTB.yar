
rule Trojan_Win32_Hancitor_FWZ_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.FWZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d8 83 c3 04 90 02 02 e8 90 01 04 2b d8 01 1d 90 01 04 83 05 90 01 05 a1 90 01 04 3b 05 90 01 04 72 90 09 29 00 2b d8 a1 90 01 04 89 18 a1 90 01 04 03 05 90 01 04 03 05 90 01 04 8b 15 90 01 04 31 02 90 02 02 e8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}