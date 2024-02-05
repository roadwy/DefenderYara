
rule Trojan_Win32_AprilAxe_C_dha{
	meta:
		description = "Trojan:Win32/AprilAxe.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 64 00 "
		
	strings :
		$a_43_0 = {84 3e fc 0f 00 00 8d 84 30 00 10 00 00 89 85 90 01 04 3b fb 74 90 01 01 8d 86 00 10 00 00 89 90 00 00 } //00 5d 
	condition:
		any of ($a_*)
 
}