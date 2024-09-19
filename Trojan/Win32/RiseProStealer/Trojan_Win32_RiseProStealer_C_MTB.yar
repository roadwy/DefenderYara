
rule Trojan_Win32_RiseProStealer_C_MTB{
	meta:
		description = "Trojan:Win32/RiseProStealer.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 8d 18 ff ff ff 8b c1 8b bd 14 ff ff ff 2b c7 8b 95 3c ff ff ff 8b b5 34 ff ff ff 42 c1 f8 ?? 83 c6 ?? 69 c0 ?? ?? ?? ?? 89 95 3c ff ff ff 89 b5 34 ff ff ff 3b d0 } //2
		$a_03_1 = {8b 8d 18 ff ff ff 8b c1 8b bd 14 ff ff ff 2b c7 c1 f8 ?? 69 c0 ab aa aa aa c7 85 3c ff ff ff } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}