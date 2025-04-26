
rule Trojan_Win32_Emotet_SAE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.SAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 11 8b 75 ?? 01 d6 89 45 ?? 89 f0 ?? 8b 75 ?? f7 fe 8b 7d } //1
		$a_03_1 = {0f b6 14 16 31 d1 8b 55 ?? 8b 32 8b 55 ?? 88 0c 32 e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}