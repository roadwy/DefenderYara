
rule Trojan_Win32_Glupteba_OF_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 08 8d [0-02] e8 [0-04] 30 ?? 83 [0-03] 90 18 47 3b [0-02] 90 18 81 [0-06] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}