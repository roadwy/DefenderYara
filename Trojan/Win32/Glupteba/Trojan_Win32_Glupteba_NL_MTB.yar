
rule Trojan_Win32_Glupteba_NL_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {50 8b 45 ec 90 18 55 8b ec 33 45 08 5d c2 } //2
		$a_02_1 = {50 8b 45 ec e8 [0-04] 81 3d [0-08] 8b [0-03] 75 } //1
		$a_02_2 = {50 8b 45 ec e8 [0-04] 81 3d [0-08] 8b [0-03] 90 18 33 [0-03] 83 [0-06] 89 [0-03] 8b [0-03] 29 } //3
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1+(#a_02_2  & 1)*3) >=3
 
}