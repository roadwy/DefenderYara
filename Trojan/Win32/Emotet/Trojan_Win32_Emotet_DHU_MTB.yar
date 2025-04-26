
rule Trojan_Win32_Emotet_DHU_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {80 f9 61 0f be c9 7c 03 83 e9 20 03 ?? 8a ?? ?? ?? 84 c9 75 e1 90 09 0a 00 8b ?? c1 ?? 13 c1 ?? 0d 0b } //1
		$a_02_1 = {8b 44 24 5c 8b 4c 24 58 8b 54 24 14 50 51 52 ff d7 8b 44 24 68 8b 54 24 20 83 c4 0c ?? ?? ?? ?? ?? ?? ?? ?? ?? 51 52 6a 00 6a 01 6a 00 50 ff 54 24 60 8b 4c 24 14 } //1
		$a_02_2 = {80 f9 61 0f b6 c9 72 03 83 e9 20 03 ?? ?? 8a ?? 84 c9 75 e2 90 09 0a 00 8b ?? c1 ?? 13 c1 ?? 0d 0b } //1
		$a_02_3 = {83 c4 40 ff 35 ?? ?? ?? ?? 8d 45 f0 ff 35 ?? ?? ?? ?? 50 53 8d 45 f8 50 ff 55 bc 50 ff 55 b8 ff 75 0c ff 75 08 ff 75 f8 ff 55 d8 57 56 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=2
 
}