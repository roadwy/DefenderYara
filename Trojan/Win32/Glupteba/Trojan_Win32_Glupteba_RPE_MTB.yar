
rule Trojan_Win32_Glupteba_RPE_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {39 ff 74 01 ea 31 19 90 01 04 81 c1 04 00 00 00 47 39 c1 75 ea 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_RPE_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {39 c9 74 01 ea 31 08 21 d3 81 c0 04 00 00 00 29 df 68 90 01 04 5a 39 f0 75 e5 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}