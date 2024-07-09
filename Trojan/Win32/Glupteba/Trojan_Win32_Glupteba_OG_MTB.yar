
rule Trojan_Win32_Glupteba_OG_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 08 8d [0-02] e8 [0-04] 30 ?? 83 [0-02] 90 18 46 3b ?? 90 18 81 [0-05] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}