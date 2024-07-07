
rule Trojan_Win32_Glupteba_GNF_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 3b 81 e8 90 01 04 01 c8 81 c3 04 00 00 00 29 c9 39 f3 90 01 02 29 c2 c3 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}