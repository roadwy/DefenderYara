
rule Trojan_Win32_Glupteba_PW_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 f8 83 [0-02] 89 [0-02] 8b [0-02] 3b [0-02] 73 ?? 83 [0-06] 90 18 8b [0-02] 89 [0-02] 81 [0-09] 90 18 8b [0-02] d1 ?? 89 [0-02] 81 [0-09] 90 18 8b [0-02] 51 8b [0-02] 8b [0-02] 8d [0-02] 51 e8 [0-04] eb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}