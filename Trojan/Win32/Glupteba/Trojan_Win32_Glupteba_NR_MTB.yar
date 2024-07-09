
rule Trojan_Win32_Glupteba_NR_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c6 c1 e8 05 03 [0-05] 03 [0-05] 03 [0-03] 33 [0-03] 33 [0-03] 89 [0-03] 89 [0-05] 89 [0-05] 8b [0-05] 29 [0-03] 8b [0-05] 29 [0-03] ff [0-05] 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}