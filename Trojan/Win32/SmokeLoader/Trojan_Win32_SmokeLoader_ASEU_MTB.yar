
rule Trojan_Win32_SmokeLoader_ASEU_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.ASEU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 03 45 90 01 01 89 45 f8 8b 45 90 01 01 31 45 fc 8b 45 fc 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}