
rule Trojan_Win32_Glupteba_NO_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c6 c1 e8 05 89 [0-03] 8d [0-03] e8 [0-04] 8d [0-03] 8b [0-03] e8 [0-04] 81 3d [0-08] 8b [0-03] 90 18 [0-0a] 33 [0-03] 83 [0-06] 89 [0-03] 8b [0-03] 29 [0-03] 81 [0-06] ff [0-06] 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}