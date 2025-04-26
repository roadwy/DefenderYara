
rule DoS_Win32_CaddyWiper_F_dha{
	meta:
		description = "DoS:Win32/CaddyWiper.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_43_0 = {5c 24 50 90 01 01 89 5c 24 38 90 01 01 89 5c 24 58 48 90 01 04 89 5c 24 60 41 b9 80 07 00 00 48 90 01 04 4d 8b c4 ba 54 c0 07 00 49 8b cd 90 00 00 } //100
	condition:
		((#a_43_0  & 1)*100) >=100
 
}