
rule Trojan_Win32_ICLoader_CCJU_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.CCJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b f9 8a 0d 40 ?? 8a 00 a0 4f ?? 8a 00 80 c9 0c 8a 1d 42 ?? 8a 00 c0 e9 02 81 e1 ff 00 00 00 32 d8 89 4c 24 } //2
		$a_03_1 = {32 d1 88 15 49 ?? 8a 00 8b 15 34 ?? 8a 00 8b 0d 48 ?? 8a 00 83 e2 04 03 c2 81 e1 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}