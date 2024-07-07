
rule Trojan_Win32_Glupteba_AFX_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.AFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 10 4e 89 ce 81 c0 90 01 04 81 c6 90 01 04 39 f8 75 e6 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}