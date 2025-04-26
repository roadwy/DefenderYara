
rule Trojan_Win32_ICLoader_BY_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {32 da 8b 15 ?? ?? 63 00 88 1d ?? ?? 63 00 bb 04 00 00 00 23 c3 81 e2 ff 00 00 00 03 f8 a1 ?? ?? 63 00 83 e0 0c 51 0f af c2 df 6c 24 1c dd 1d } //4
		$a_01_1 = {8b d7 8b c6 5f 5e 5b 83 c4 14 c3 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}