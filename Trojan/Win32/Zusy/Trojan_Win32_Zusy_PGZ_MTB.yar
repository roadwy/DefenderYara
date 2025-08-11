
rule Trojan_Win32_Zusy_PGZ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.PGZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 3b 09 c8 81 c3 04 00 00 00 46 46 39 d3 75 eb } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}