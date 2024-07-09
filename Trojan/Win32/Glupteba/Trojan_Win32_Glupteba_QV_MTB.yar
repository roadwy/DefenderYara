
rule Trojan_Win32_Glupteba_QV_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.QV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 5d 74 89 [0-05] 89 [0-05] 8b [0-05] 29 [0-02] 81 3d [0-08] 90 18 8b [0-05] 29 [0-02] ff [0-05] 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}