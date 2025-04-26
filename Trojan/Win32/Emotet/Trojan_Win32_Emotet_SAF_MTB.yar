
rule Trojan_Win32_Emotet_SAF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.SAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 f9 81 e1 ?? ?? ?? ?? 8b 7d ?? 8b 75 ?? 8a 1c 37 8b 75 ?? 32 1c 0e 8b 4d ?? 8b 75 ?? 88 1c 31 81 c6 ?? ?? ?? ?? 8b 4d ?? 39 ce 8b 4d ?? 89 75 ?? 89 4d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}