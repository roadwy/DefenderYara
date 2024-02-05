
rule Trojan_Win32_plugx_psyB_MTB{
	meta:
		description = "Trojan:Win32/plugx.psyB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {33 d2 8a d4 89 15 94 e5 42 00 8b c8 81 e1 ff 00 00 00 89 0d 90 e5 42 00 c1 e1 08 03 ca 89 0d 8c e5 42 00 c1 e8 10 a3 88 e5 42 00 33 f6 56 } //00 00 
	condition:
		any of ($a_*)
 
}