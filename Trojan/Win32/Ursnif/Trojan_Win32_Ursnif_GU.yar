
rule Trojan_Win32_Ursnif_GU{
	meta:
		description = "Trojan:Win32/Ursnif.GU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 00 4b 00 4c 00 45 00 48 00 4c 00 40 00 4b 00 23 00 6e 00 77 00 6b 00 6e 00 62 00 } //01 00 
		$a_01_1 = {5c 47 57 48 57 45 52 57 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}