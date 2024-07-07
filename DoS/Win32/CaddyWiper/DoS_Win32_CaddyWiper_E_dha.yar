
rule DoS_Win32_CaddyWiper_E_dha{
	meta:
		description = "DoS:Win32/CaddyWiper.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_43_0 = {c0 50 6a 10 50 e8 90 01 04 59 59 53 8d 85 90 01 04 50 53 53 68 80 07 00 00 ff 90 01 02 68 54 c0 07 00 ff 90 01 02 ff 90 01 02 eb 90 00 00 } //100
	condition:
		((#a_43_0  & 1)*100) >=100
 
}