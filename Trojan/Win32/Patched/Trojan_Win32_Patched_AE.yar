
rule Trojan_Win32_Patched_AE{
	meta:
		description = "Trojan:Win32/Patched.AE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 00 10 e0 8d 0f 51 ff 10 } //01 00 
		$a_01_1 = {68 3f 00 5c 00 68 5c 00 3f 00 66 89 47 1c 89 67 20 be 0d 01 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}