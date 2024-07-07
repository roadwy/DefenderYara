
rule Trojan_Win32_Glupteba_GZF_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 de 81 ee 90 01 04 31 01 41 01 f6 81 c3 90 01 04 39 d1 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}