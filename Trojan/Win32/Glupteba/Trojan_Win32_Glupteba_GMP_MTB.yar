
rule Trojan_Win32_Glupteba_GMP_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {31 19 47 81 c1 04 00 00 00 39 f1 75 90 01 01 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}