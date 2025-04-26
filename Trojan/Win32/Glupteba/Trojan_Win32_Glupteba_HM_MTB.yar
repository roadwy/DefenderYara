
rule Trojan_Win32_Glupteba_HM_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.HM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 0a 21 ff 42 21 db bb 1f 0a 34 ab 39 f2 75 e5 81 ef 94 b7 01 e0 c3 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}