
rule Trojan_Win32_Glupteba_NM_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 74 24 10 33 f1 2b fe 81 3d [0-08] 75 [0-02] 6a 00 6a 00 ff 15 [0-04] 8b [0-06] 29 [0-03] 83 [0-08] 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}