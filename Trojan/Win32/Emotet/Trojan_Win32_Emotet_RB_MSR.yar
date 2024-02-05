
rule Trojan_Win32_Emotet_RB_MSR{
	meta:
		description = "Trojan:Win32/Emotet.RB!MSR,SIGNATURE_TYPE_PEHSTR,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {43 61 73 63 61 64 65 5f 43 6c 31 32 32 35 39 35 38 32 36 32 30 30 32 5c 52 65 6c 65 61 73 65 5c 43 61 73 63 61 64 65 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}