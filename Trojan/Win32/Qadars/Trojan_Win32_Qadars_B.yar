
rule Trojan_Win32_Qadars_B{
	meta:
		description = "Trojan:Win32/Qadars.B,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 64 00 "
		
	strings :
		$a_01_0 = {d6 d4 9d 6a aa 6e 89 0f 3e 91 37 38 39 5f 5f 4b 45 59 5f 5f } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qadars_B_2{
	meta:
		description = "Trojan:Win32/Qadars.B,SIGNATURE_TYPE_ARHSTR_EXT,64 00 64 00 01 00 00 64 00 "
		
	strings :
		$a_01_0 = {d6 d4 9d 6a aa 6e 89 0f 3e 91 37 38 39 5f 5f 4b 45 59 5f 5f } //0a 00 
	condition:
		any of ($a_*)
 
}