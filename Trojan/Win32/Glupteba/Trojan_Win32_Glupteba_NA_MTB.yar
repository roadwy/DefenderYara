
rule Trojan_Win32_Glupteba_NA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d7 c1 ea 05 8d [0-06] 89 [0-06] 8b [0-06] 01 [0-06] 03 [0-06] 33 [0-06] 81 [0-09] c7 05 [0-08] 90 18 31 [0-03] 81 [0-09] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}