
rule Trojan_Win32_Glupteba_NZ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 16 42 3b d7 90 18 90 18 55 8b ec 51 a1 [0-04] 69 [0-05] a3 [0-04] c7 45 [0-05] 81 45 [0-05] 8b [0-05] 01 [0-05] 0f [0-06] 25 [0-04] 8b e5 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}