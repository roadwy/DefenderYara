
rule Trojan_Win32_Azorult_MW_MTB{
	meta:
		description = "Trojan:Win32/Azorult.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 01 83 fb ?? 90 18 47 3b fb 90 18 8b 45 08 8d [0-02] e8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}