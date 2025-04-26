
rule Trojan_Win32_Glupteba_QT_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.QT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 0f 21 d8 81 c7 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 39 d7 75 e7 81 c6 ?? ?? ?? ?? c3 81 c1 ?? ?? ?? ?? 39 c7 75 e3 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Glupteba_QT_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.QT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 [0-02] 8b [0-02] 03 [0-02] 89 [0-02] 8b [0-02] 33 [0-02] 89 [0-02] 8b [0-02] 33 [0-02] 89 [0-02] 8b [0-02] 29 [0-02] c7 [0-06] 8b [0-02] 01 [0-02] 8b [0-02] 2b [0-02] 89 [0-02] e9 } //1
		$a_02_1 = {c1 ea 05 89 [0-02] 8b [0-02] 03 [0-02] 89 [0-02] 8b [0-02] 33 [0-02] 89 [0-02] 8b [0-02] 33 [0-02] 89 [0-02] 8b [0-02] 29 [0-02] 8b [0-02] 29 [0-02] e9 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}