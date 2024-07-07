
rule Trojan_Win32_Glupteba_SPDL_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.SPDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 31 09 d3 81 c1 04 00 00 00 01 d3 39 c1 75 eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}