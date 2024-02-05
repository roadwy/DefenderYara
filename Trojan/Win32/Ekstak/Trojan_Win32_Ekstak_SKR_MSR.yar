
rule Trojan_Win32_Ekstak_SKR_MSR{
	meta:
		description = "Trojan:Win32/Ekstak.SKR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c8 03 cf 30 11 83 3d 90 01 03 00 02 90 13 3d 44 07 00 00 90 0a 1d 00 8a 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}