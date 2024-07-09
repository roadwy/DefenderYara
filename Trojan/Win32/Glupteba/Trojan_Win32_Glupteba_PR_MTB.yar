
rule Trojan_Win32_Glupteba_PR_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b e5 5d c2 08 00 90 09 3e 00 8b [0-02] 33 [0-02] 89 [0-02] 8b [0-02] 33 [0-02] 89 [0-02] 8b [0-02] 2b [0-02] 89 [0-02] 8b [0-02] 51 8d [0-02] 52 e8 [0-04] e9 [0-04] 8b [0-02] 8b [0-02] 89 [0-01] 8b [0-02] 8b [0-02] 89 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}