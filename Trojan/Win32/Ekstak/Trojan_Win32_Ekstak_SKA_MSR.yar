
rule Trojan_Win32_Ekstak_SKA_MSR{
	meta:
		description = "Trojan:Win32/Ekstak.SKA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 14 02 88 14 39 8a 88 90 01 03 00 84 c9 75 12 8b 0d 90 01 03 00 8a 15 90 01 03 00 03 c8 03 cf 30 11 40 3d 44 07 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}