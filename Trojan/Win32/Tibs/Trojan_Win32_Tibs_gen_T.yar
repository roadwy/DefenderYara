
rule Trojan_Win32_Tibs_gen_T{
	meta:
		description = "Trojan:Win32/Tibs.gen!T,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 6e c0 0f 6f c8 0f 7e c8 48 83 f8 00 75 f1 8b 04 24 83 c4 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}