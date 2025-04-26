
rule Trojan_Win32_Glupteba_PV_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 55 e4 33 [0-02] 89 [0-02] 8b [0-02] 33 [0-02] 89 [0-02] 8b [0-02] 2b [0-02] 89 [0-02] 8b [0-02] 2b [0-02] 89 [0-02] e9 [0-04] 8b [0-02] 8b [0-02] 89 08 8b [0-02] 8b [0-02] 89 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}