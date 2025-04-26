
rule Trojan_Win32_Glupteba_PJ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 54 24 10 8b [0-03] 33 ?? 33 ?? 8d [0-06] 89 [0-03] e8 [0-04] 81 [0-05] 83 [0-07] 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}