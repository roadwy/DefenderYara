
rule Trojan_Win32_Netvat_E_Dll{
	meta:
		description = "Trojan:Win32/Netvat.E!Dll,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 75 5f 68 6f 6f 6b 00 25 73 25 73 2e 65 78 65 } //01 00 
		$a_01_1 = {69 76 75 73 38 2e 2a 6f 61 70 72 63 64 61 70 2f 7b 6a 62 72 2f 6b 67 70 39 38 } //00 00 
	condition:
		any of ($a_*)
 
}