
rule Trojan_Win32_Glupteba_OW_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f5 c1 e6 04 81 3d [0-08] 90 18 03 [0-06] 81 [0-0d] 90 18 8b ?? c1 [0-02] c7 05 [0-08] c7 05 [0-08] 89 [0-03] 8b [0-06] 01 [0-03] 81 3d [0-08] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}