
rule Trojan_Win32_Glupteba_QM_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.QM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 89 [0-02] 8b [0-02] 03 [0-02] 89 [0-02] 8b [0-02] 33 [0-02] 89 [0-02] 8b [0-02] 33 [0-02] 89 [0-02] 8b [0-02] 29 [0-02] 81 3d [0-08] 90 18 8b [0-02] 2b [0-02] 89 [0-02] e9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_QM_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.QM!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 c7 45 fc 00 00 00 00 8b 45 0c 01 45 fc 8b 45 08 8b 08 33 4d fc 8b 55 08 89 0a 8b e5 5d c2 08 00 } //10
		$a_01_1 = {03 4d 08 8b 55 fc 03 55 08 8a 02 88 01 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}