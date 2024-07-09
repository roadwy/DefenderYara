
rule Trojan_Win32_Ekstak_SKA_MSR{
	meta:
		description = "Trojan:Win32/Ekstak.SKA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 14 02 88 14 39 8a 88 ?? ?? ?? 00 84 c9 75 12 8b 0d ?? ?? ?? 00 8a 15 ?? ?? ?? 00 03 c8 03 cf 30 11 40 3d 44 07 00 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}