
rule DoS_Win32_CaddyWiper_G_dha{
	meta:
		description = "DoS:Win32/CaddyWiper.G!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_43_0 = {78 30 01 75 90 01 01 8b 90 01 05 53 8d 90 01 05 51 53 53 68 80 07 00 00 50 68 54 c0 07 00 52 89 58 50 89 58 54 89 58 58 89 58 5c ff 90 00 00 } //100
	condition:
		((#a_43_0  & 1)*100) >=100
 
}