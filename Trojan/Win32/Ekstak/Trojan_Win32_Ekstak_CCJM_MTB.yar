
rule Trojan_Win32_Ekstak_CCJM_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.CCJM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {32 c8 56 88 0d ?? ?? 4c 00 8a 0d 43 40 4c 00 80 c9 08 8b b4 24 b8 00 00 00 c0 e9 03 81 e1 ff 00 00 00 6a 05 } //2
		$a_01_1 = {32 c2 a2 46 40 4c 00 0c 30 c0 e8 04 25 ff } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}