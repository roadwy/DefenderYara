
rule Trojan_Win32_Azorult_NR_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 3b 83 7d [0-02] 90 18 47 3b 7d 08 90 18 81 7d [0-05] 90 18 e8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}