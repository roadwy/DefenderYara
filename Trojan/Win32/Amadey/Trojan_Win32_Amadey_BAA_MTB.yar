
rule Trojan_Win32_Amadey_BAA_MTB{
	meta:
		description = "Trojan:Win32/Amadey.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 14 02 32 94 8d ?? ?? ?? ?? 8b 45 18 8b 08 8b 85 ?? ?? ?? ?? 88 14 01 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}