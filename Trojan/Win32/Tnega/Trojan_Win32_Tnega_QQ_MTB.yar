
rule Trojan_Win32_Tnega_QQ_MTB{
	meta:
		description = "Trojan:Win32/Tnega.QQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 34 24 83 c4 04 29 c6 e8 90 01 04 46 31 1a 81 ee 90 01 04 42 56 8b 04 24 83 c4 04 39 ca 75 d7 29 f0 09 c0 c3 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}