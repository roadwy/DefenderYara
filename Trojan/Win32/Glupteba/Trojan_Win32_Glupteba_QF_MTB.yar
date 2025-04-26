
rule Trojan_Win32_Glupteba_QF_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.QF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 d4 01 [0-02] 81 3d [0-08] 90 18 8b [0-02] 33 [0-02] 89 [0-02] 8b [0-02] 33 [0-02] 89 [0-02] 8b [0-02] 2b [0-02] 89 [0-02] 8b [0-02] 50 8d [0-02] 51 e8 [0-04] e9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}