
rule Trojan_Win32_Glupteba_NU_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b f0 c1 ee 05 03 [0-05] 81 3d [0-08] c7 05 [0-08] c7 05 [0-08] 90 18 33 [0-03] 81 [0-0a] 33 [0-03] 2b [0-03] 83 [0-05] 0f 85 } //1
		$a_02_1 = {c1 ee 05 03 [0-03] 81 3d [0-08] c7 05 [0-08] c7 05 [0-08] 90 18 [0-08] 33 [0-03] 33 [0-0c] 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}