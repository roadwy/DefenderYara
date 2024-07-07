
rule Trojan_Win32_Amadey_LDP_MTB{
	meta:
		description = "Trojan:Win32/Amadey.LDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 d3 e8 89 45 f8 8b 45 e0 01 45 f8 8b 45 f8 8b 4d 90 01 01 33 45 f4 33 c8 2b f9 89 4d 90 01 01 8d 4d 90 01 01 89 7d e8 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}