
rule Trojan_Win32_NativeZone_I_dha{
	meta:
		description = "Trojan:Win32/NativeZone.I!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 64 00 "
		
	strings :
		$a_41_0 = {b8 30 be 7c 96 b5 04 c7 6e 48 ba 73 26 05 46 9e ac 17 f2 00 } //00 7e 
	condition:
		any of ($a_*)
 
}