
rule Trojan_Win32_Glupteba_NK_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c7 c1 e8 05 03 [0-05] 03 [0-05] 03 [0-03] 33 [0-03] 81 3d [0-08] 89 [0-03] 90 18 [0-0a] 33 [0-03] 89 [0-05] 8b [0-05] 29 [0-03] 81 [0-0a] ff [0-05] 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}