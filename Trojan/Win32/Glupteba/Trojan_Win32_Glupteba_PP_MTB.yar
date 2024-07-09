
rule Trojan_Win32_Glupteba_PP_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {eb 0d 8b 85 [0-04] 40 89 85 [0-04] 81 bd [0-08] 7d 10 83 bd [0-05] 75 05 e8 [0-04] eb d7 68 [0-04] ff 35 [0-04] ff 35 [0-04] e8 [0-04] e8 [0-04] 33 c0 5f 5e c9 c2 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}