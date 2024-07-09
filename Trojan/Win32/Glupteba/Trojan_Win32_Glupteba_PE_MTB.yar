
rule Trojan_Win32_Glupteba_PE_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b ce c1 e1 04 03 [0-06] 8b ?? c1 [0-02] 89 [0-03] 89 [0-03] 8b [0-06] 01 [0-03] 8b [0-03] 8d [0-02] 33 ?? 31 [0-03] 83 [0-06] c7 [0-09] 89 [0-03] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}