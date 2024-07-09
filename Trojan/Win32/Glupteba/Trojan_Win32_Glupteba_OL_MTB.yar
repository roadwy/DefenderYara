
rule Trojan_Win32_Glupteba_OL_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 c7 05 [0-08] c7 05 [0-08] 89 [0-03] 8b [0-03] 01 [0-03] 8b [0-07] 33 ?? 33 [0-03] 68 [0-04] 8d [0-03] 51 2b ?? e8 [0-04] 83 [0-04] 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}