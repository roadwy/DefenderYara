
rule Trojan_Win32_Ptredo_YAC_MTB{
	meta:
		description = "Trojan:Win32/Ptredo.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 ec 03 45 e0 0f b6 48 ff 33 d1 8b 45 ec 03 45 e0 88 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}