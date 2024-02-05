
rule Trojan_Win32_Ursnif_C{
	meta:
		description = "Trojan:Win32/Ursnif.C,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 5c 33 5c 2e 34 31 5c 2e 33 34 44 4c 4f 70 65 72 61 74 69 6e 67 53 79 6b 33 34 35 36 62 62 } //00 00 
	condition:
		any of ($a_*)
 
}