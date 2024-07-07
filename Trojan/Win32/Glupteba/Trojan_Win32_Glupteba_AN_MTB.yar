
rule Trojan_Win32_Glupteba_AN_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {09 d7 ba 06 bc 76 9d 31 0b 81 ea 90 01 04 43 57 5a 39 f3 75 e0 57 5f 68 90 01 04 8b 14 24 83 c4 04 c3 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}