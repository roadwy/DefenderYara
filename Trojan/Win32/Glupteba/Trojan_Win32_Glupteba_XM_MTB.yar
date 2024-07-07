
rule Trojan_Win32_Glupteba_XM_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.XM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {4a 39 c3 75 90 01 01 83 ec 90 01 01 89 0c 24 8b 3c 24 83 c4 90 01 01 c3 90 0a 30 00 31 33 ba 90 01 04 81 c3 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}