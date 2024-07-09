
rule Trojan_Win32_Glupteba_QW_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.QW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 89 [0-02] 8b [0-02] 03 [0-02] 89 [0-02] 8b [0-02] 33 [0-02] 89 [0-02] 8b [0-02] 33 [0-02] 89 [0-02] 8b [0-02] 29 [0-02] 8b [0-02] 50 8d [0-02] 51 e8 [0-04] e9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_QW_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.QW!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 04 89 01 c3 55 8b ec 51 83 65 fc 00 8b 45 08 01 45 fc 8b 45 fc 31 01 c9 c2 04 00 33 44 24 04 c2 04 00 } //10
		$a_01_1 = {01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}