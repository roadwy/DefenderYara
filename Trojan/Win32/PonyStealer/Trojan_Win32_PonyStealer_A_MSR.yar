
rule Trojan_Win32_PonyStealer_A_MSR{
	meta:
		description = "Trojan:Win32/PonyStealer.A!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 1c 08 89 1c 08 89 1c 08 89 1c 08 89 1c 08 89 1c 08 89 1c 08 89 1c 08 89 1c 08 } //02 00 
		$a_01_1 = {85 f6 85 c0 85 db 33 1c 24 85 c9 90 85 c0 90 85 db } //01 00 
		$a_01_2 = {85 f6 85 d2 85 f6 85 f6 85 f6 85 c0 90 } //00 00 
	condition:
		any of ($a_*)
 
}