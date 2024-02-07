
rule Trojan_Win32_Rozena_GM_MTB{
	meta:
		description = "Trojan:Win32/Rozena.GM!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {fe c0 02 1c 07 8a 14 07 86 14 1f 88 14 07 02 14 1f 8a 14 17 30 55 00 45 49 75 } //01 00 
		$a_01_1 = {44 56 49 49 49 44 61 2e 6d 2e 44 6b 63 61 6c 44 70 2e 6d 2e 44 76 69 69 69 44 } //00 00  DVIIIDa.m.DkcalDp.m.DviiiD
	condition:
		any of ($a_*)
 
}