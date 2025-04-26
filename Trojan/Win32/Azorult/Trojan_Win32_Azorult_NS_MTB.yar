
rule Trojan_Win32_Azorult_NS_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 14 8d [0-02] e8 [0-04] 30 ?? 83 ?? ?? 90 18 43 3b dd 90 18 81 fd [0-04] 75 15 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}