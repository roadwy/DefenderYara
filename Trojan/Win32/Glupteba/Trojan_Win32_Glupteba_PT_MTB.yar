
rule Trojan_Win32_Glupteba_PT_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 [0-02] 8b [0-02] 01 [0-02] 8b [0-02] 33 [0-02] 89 [0-02] 8b [0-02] 33 [0-02] 89 [0-02] 8b [0-02] 2b [0-02] 89 [0-02] 8b [0-02] 29 [0-02] e9 [0-04] 8b [0-02] 8b [0-02] 89 ?? 8b [0-02] 8b [0-02] 89 [0-02] 8b e5 5d c2 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}