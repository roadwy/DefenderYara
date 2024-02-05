
rule Trojan_Win32_Trickbot_AA{
	meta:
		description = "Trojan:Win32/Trickbot.AA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {43 3a 5c 55 73 65 72 73 5c 55 73 65 72 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 30 38 5c 50 72 6f 6a 65 63 74 73 5c 53 74 75 70 69 64 20 57 69 6e 64 69 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 52 65 6c 65 61 73 65 5c 90 02 20 2e 70 64 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}