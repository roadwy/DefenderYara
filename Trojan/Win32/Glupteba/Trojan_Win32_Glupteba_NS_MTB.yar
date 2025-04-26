
rule Trojan_Win32_Glupteba_NS_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {75 08 50 50 ff 15 [0-04] e8 [0-04] 30 [0-03] 33 [0-03] 3b [0-03] 90 18 81 } //1
		$a_02_1 = {55 8b ec 51 51 56 33 f6 81 3d [0-08] 90 18 a1 [0-04] 69 [0-05] 81 3d [0-08] [0-08] a3 [0-04] 90 18 89 [0-03] 81 [0-06] 8b [0-03] 01 [0-05] 0f [0-06] 25 [0-04] 5e c9 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}