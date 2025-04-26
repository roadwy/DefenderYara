
rule Trojan_Win32_Azorult_NH_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 0c 8d [0-02] e8 [0-04] 30 ?? 47 3b fb 90 18 81 fb [0-04] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}