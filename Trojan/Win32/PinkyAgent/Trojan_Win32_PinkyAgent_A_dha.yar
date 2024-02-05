
rule Trojan_Win32_PinkyAgent_A_dha{
	meta:
		description = "Trojan:Win32/PinkyAgent.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 64 00 "
		
	strings :
		$a_01_0 = {63 64 20 43 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 73 65 72 76 69 63 65 5c 63 6f 72 65 20 26 26 20 63 6d 64 2e 65 78 65 20 2f 43 20 22 22 43 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 57 69 6e 64 6f 77 73 20 45 76 65 6e 74 73 2e 65 78 65 22 20 22 43 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 73 65 72 76 69 63 65 5c 63 6f 72 65 5c 61 67 65 6e 74 2e 70 79 22 22 } //00 00 
	condition:
		any of ($a_*)
 
}