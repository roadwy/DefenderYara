
rule Trojan_Win32_RedLineStealer_BAA_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 16 8b c2 42 83 e0 ?? 8a 04 38 8b 7d ?? 32 04 39 88 01 3b 95 ?? ?? ?? ?? 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}