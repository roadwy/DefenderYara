
rule Trojan_Win32_Glupteba_MN_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b cf c1 e9 05 89 [0-03] 8b [0-0a] 01 44 24 10 8b f7 c1 e6 04 03 b4 24 [0-04] 8d [0-03] 33 f2 81 3d [0-08] c7 05 [0-08] 90 18 31 [0-04] 81 [0-09] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}