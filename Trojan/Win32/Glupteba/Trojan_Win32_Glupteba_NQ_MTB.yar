
rule Trojan_Win32_Glupteba_NQ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 d1 31 55 ?? 8b [0-03] 8d [0-05] e8 [0-04] 81 3d [0-08] 75 } //1
		$a_02_1 = {33 45 70 83 25 [0-08] 8b c8 89 45 [0-01] 8d [0-05] e8 [0-04] 81 [0-05] ff [0-05] 0f } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}