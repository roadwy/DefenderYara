
rule Trojan_Win32_Glupteba_OE_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b d7 c1 e2 04 03 ?? 33 [0-03] 33 ?? 2b ?? 81 [0-09] 90 18 8b [0-06] 29 [0-03] 83 [0-07] 0f 85 } //1
		$a_02_1 = {8b d7 c1 ea ?? 8d [0-02] c7 [0-09] c7 [0-09] 89 [0-03] 8b [0-06] 01 [0-03] 8b ?? c1 ?? ?? 03 ?? 33 [0-03] 33 ?? 2b ?? 81 [0-09] 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}