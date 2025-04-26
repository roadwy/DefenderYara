
rule DoS_Win32_CaddyWiper_D_dha{
	meta:
		description = "DoS:Win32/CaddyWiper.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_43_0 = {a1 30 00 00 00 8b 40 0c 8b 40 14 8b 48 10 8b 45 90 01 01 99 83 e2 03 03 c2 56 c1 f8 02 33 f6 57 8b f9 85 c0 7e 90 00 00 } //100
	condition:
		((#a_43_0  & 1)*100) >=100
 
}