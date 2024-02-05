
rule Trojan_Win32_Podjot_A{
	meta:
		description = "Trojan:Win32/Podjot.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_11_0 = {6f 6f 6b 6f 6f 64 6f 6f 5f 70 72 6f 6a 78 2e 64 6c 6c 00 53 74 61 72 74 75 70 00 } //00 87 
	condition:
		any of ($a_*)
 
}