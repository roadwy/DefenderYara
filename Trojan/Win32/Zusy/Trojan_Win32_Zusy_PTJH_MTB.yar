
rule Trojan_Win32_Zusy_PTJH_MTB{
	meta:
		description = "Trojan:Win32/Zusy.PTJH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 bb 00 00 00 00 01 d3 31 03 5b 5a 68 46 fd 6d 1c 89 04 24 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}