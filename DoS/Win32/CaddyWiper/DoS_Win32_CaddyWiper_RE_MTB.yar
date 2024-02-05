
rule DoS_Win32_CaddyWiper_RE_MTB{
	meta:
		description = "DoS:Win32/CaddyWiper.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 08 03 45 f4 8a 4d fb 88 08 8b 55 f4 83 c2 01 89 55 f4 8b 45 0c 03 45 f4 8a 08 88 4d fb } //00 00 
	condition:
		any of ($a_*)
 
}