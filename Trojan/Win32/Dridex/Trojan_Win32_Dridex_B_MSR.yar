
rule Trojan_Win32_Dridex_B_MSR{
	meta:
		description = "Trojan:Win32/Dridex.B!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 54 6f 70 5c 54 72 61 69 6e 5c 6a 6f 62 5c 57 61 6c 6c 5c 44 69 64 5c 53 70 65 6e 64 6b 65 70 74 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}