
rule Trojan_Win32_Tibs_gen_S{
	meta:
		description = "Trojan:Win32/Tibs.gen!S,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 db 00 00 01 00 01 df 83 ef 01 83 ef 01 83 ef 02 81 ef 00 70 00 00 81 ef 00 60 00 00 81 ef 00 30 00 00 e2 b4 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}