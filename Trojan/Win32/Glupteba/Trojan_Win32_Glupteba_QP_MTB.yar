
rule Trojan_Win32_Glupteba_QP_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.QP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {be d8 85 40 00 09 c0 e8 ?? ?? ?? ?? 31 33 43 68 ?? ?? ?? ?? 58 48 39 d3 75 e6 48 21 f8 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Glupteba_QP_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.QP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 [0-02] 8b [0-02] 03 [0-02] 89 [0-02] 8b [0-02] 33 [0-02] 89 [0-02] 8b [0-02] 33 [0-02] 89 [0-02] 8b [0-02] 29 [0-02] 8b [0-02] 29 [0-02] e9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}