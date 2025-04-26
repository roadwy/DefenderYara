
rule Trojan_Win32_ICLoader_CCJV_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.CCJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af d1 23 c2 8b 54 24 ?? 52 a3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b f0 56 ff 15 ?? ?? ?? ?? a0 41 b0 79 00 8a 0d 4b b0 79 00 32 c8 8b 1d 80 80 79 00 88 0d 4b b0 79 00 8a 0d 42 b0 79 00 80 c9 10 6a 0c c0 e9 03 81 e1 ff 00 00 00 56 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}