
rule Trojan_Win32_Azorult_NT_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 14 8d [0-02] e8 [0-04] 30 ?? 81 [0-05] 90 18 43 3b dd 90 18 81 [0-05] 75 15 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}