
rule Trojan_Win32_Glupteba_OK_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b cf c1 e9 05 89 [0-03] 8b [0-03] 01 [0-03] 8b ?? c1 e6 ?? 03 [0-03] 8d [0-02] 33 ?? 81 [0-09] c7 [0-09] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}