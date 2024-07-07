
rule Trojan_Win32_Tibs_IW{
	meta:
		description = "Trojan:Win32/Tibs.IW,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f3 0f 7e 26 89 e8 66 0f 7e e0 83 c6 02 83 c6 02 f8 73 90 01 01 50 f3 0f 7e 0c 24 fc 58 66 0f 7e 0f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}