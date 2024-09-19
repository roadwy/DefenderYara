
rule Trojan_Win32_Ekstak_CCJC_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.CCJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 56 8b 74 24 0c 57 c7 06 00 00 00 00 a1 ?? ?? 65 00 50 e8 ?? ?? 20 00 8b 3d ?? ?? 65 00 6a 12 a3 ?? ?? 65 00 ff d7 66 85 c0 6a 10 0f 95 c3 ff d7 66 85 c0 7d } //1
		$a_03_1 = {55 8b ec 51 56 57 68 ?? ?? 65 00 e8 ?? ?? fb ff 8b ?? e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}