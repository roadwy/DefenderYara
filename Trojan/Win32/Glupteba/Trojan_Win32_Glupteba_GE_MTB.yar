
rule Trojan_Win32_Glupteba_GE_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 c9 31 3a 41 81 c2 01 00 00 00 41 39 da 75 e4 01 c0 c3 29 c0 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}