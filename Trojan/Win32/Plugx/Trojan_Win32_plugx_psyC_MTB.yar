
rule Trojan_Win32_plugx_psyC_MTB{
	meta:
		description = "Trojan:Win32/plugx.psyC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {07 08 9a 0d 09 6f 15 00 00 0a 72 01 00 00 70 28 16 00 00 0a 2c 28 09 6f 17 00 00 0a 20 0e 00 02 00 12 00 28 01 00 00 06 2d 01 2a 06 28 03 00 00 06 26 09 6f 17 00 00 0a 28 02 00 00 06 26 08 17 58 0c 08 } //00 00 
	condition:
		any of ($a_*)
 
}