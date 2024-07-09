
rule Trojan_Win32_Glupteba_NF_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 33 09 fa 09 ff 43 39 cb 75 90 0a 27 00 be ?? ?? ?? ?? 47 e8 ?? ?? ?? ?? 81 ef } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Glupteba_NF_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 8d [0-03] c7 05 [0-12] 89 [0-03] 8b [0-06] 01 [0-03] 03 [0-03] 33 [0-03] 33 [0-03] 2b [0-03] 81 3d [0-08] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}