
rule Trojan_Win32_Glupteba_GMP_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 19 47 81 c1 04 00 00 00 39 f1 75 ?? c3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}