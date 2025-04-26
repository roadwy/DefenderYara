
rule Trojan_Win32_RedLine_SPXF_MTB{
	meta:
		description = "Trojan:Win32/RedLine.SPXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ff 2d 75 0e 6a 00 6a 00 ff d5 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 1e 46 3b f7 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}