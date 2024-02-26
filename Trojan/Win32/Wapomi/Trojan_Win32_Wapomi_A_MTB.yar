
rule Trojan_Win32_Wapomi_A_MTB{
	meta:
		description = "Trojan:Win32/Wapomi.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {c7 45 94 47 65 74 50 c7 45 98 72 6f 63 41 c7 45 9c 64 64 72 65 c7 45 a0 73 73 } //02 00 
		$a_01_1 = {c7 45 94 57 72 69 74 c7 45 98 65 46 69 6c c7 45 9c 65 } //02 00 
		$a_01_2 = {c7 45 94 43 6c 6f 73 c7 45 98 65 48 61 6e c7 45 9c 64 6c 65 } //02 00 
		$a_01_3 = {c7 45 94 57 69 6e 45 c7 45 98 78 65 63 } //00 00 
	condition:
		any of ($a_*)
 
}