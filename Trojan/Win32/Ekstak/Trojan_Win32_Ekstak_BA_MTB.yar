
rule Trojan_Win32_Ekstak_BA_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 e0 0f 85 c0 75 ?? 8b 4d ?? 83 e9 10 89 } //1
		$a_02_1 = {03 76 0b 8b 55 ?? 83 c2 01 89 55 ?? eb 02 ff e1 81 7d ?? 04 05 00 00 7e 04 33 c0 eb } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}