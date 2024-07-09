
rule Trojan_Win32_Tibs_IV{
	meta:
		description = "Trojan:Win32/Tibs.IV,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f3 0f 7e 26 66 0f 7e e0 83 c6 02 83 c6 02 f8 73 ?? 50 f3 0f 7e 14 24 58 66 0f 7e 17 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}