
rule Trojan_Win32_Glupteba_UM_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.UM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 14 24 83 c4 90 01 01 53 5b e8 90 01 04 68 90 01 04 5b 31 17 be 90 01 04 01 de 47 39 c7 75 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}