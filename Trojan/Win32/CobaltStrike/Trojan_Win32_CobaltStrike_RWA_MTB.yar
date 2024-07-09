
rule Trojan_Win32_CobaltStrike_RWA_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 [0-0a] 01 10 00 00 } //1
		$a_03_1 = {2b d8 01 5d ?? 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 ?? c7 45 ?? 00 10 00 00 8b [0-0a] 83 c0 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}