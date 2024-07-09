
rule Trojan_Win32_Azorult_NQ_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 3b 83 [0-03] 90 18 47 3b 7d 08 90 18 81 7d [0-05] 90 18 90 18 a1 [0-04] 69 [0-05] 05 [0-04] a3 [0-04] 0f [0-06] 25 [0-04] c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}