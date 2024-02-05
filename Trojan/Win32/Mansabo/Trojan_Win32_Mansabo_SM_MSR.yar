
rule Trojan_Win32_Mansabo_SM_MSR{
	meta:
		description = "Trojan:Win32/Mansabo.SM!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 72 32 6d 50 26 26 55 43 64 33 29 2b 47 64 } //01 00 
		$a_02_1 = {8b 44 24 20 8b 08 8b 54 24 14 51 50 68 90 01 03 00 55 6a 01 55 52 ff 15 90 01 03 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}