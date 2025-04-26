
rule Trojan_Win32_Qshell_MR_MTB{
	meta:
		description = "Trojan:Win32/Qshell.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {01 02 8b 45 ?? 05 [0-04] 03 [0-02] 8b [0-02] 31 ?? 83 [0-03] 83 [0-03] 8b [0-02] 3b [0-02] 90 18 8b [0-02] 8b } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}