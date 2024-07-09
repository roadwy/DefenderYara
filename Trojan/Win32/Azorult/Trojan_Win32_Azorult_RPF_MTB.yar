
rule Trojan_Win32_Azorult_RPF_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 fa 5f 01 da 81 ea ?? ?? ?? ?? 53 bb 00 00 00 00 01 d3 01 0b 5b 5a 5b 81 ec 04 00 00 00 89 3c 24 68 04 00 00 00 5f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}