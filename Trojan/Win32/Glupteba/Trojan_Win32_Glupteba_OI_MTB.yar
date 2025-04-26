
rule Trojan_Win32_Glupteba_OI_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b d3 c1 ea 05 8d [0-02] c7 [0-09] c7 [0-09] 89 [0-03] 8b [0-03] 01 [0-03] 8b ?? c1 [0-02] 03 [0-03] 33 [0-03] 33 ?? ?? ?? 81 [0-09] 75 } //1
		$a_02_1 = {8b cd c1 e9 05 c7 05 [0-08] c7 05 [0-08] 89 [0-03] 8b [0-06] 01 [0-03] 8b [0-03] 33 [0-03] 33 [0-03] 81 3d [0-08] 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}