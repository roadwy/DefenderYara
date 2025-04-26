
rule Trojan_Win32_ICLoader_BW_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.BW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {32 c8 6a 00 88 0d ?? ?? 63 00 8a 0d ?? ?? 63 00 80 c9 0c 6a 00 c0 e9 02 81 e1 ff 00 00 00 89 4c 24 08 db 44 24 08 dc 3d } //4
		$a_03_1 = {0f af d1 23 c2 a3 ?? ?? 63 00 8b 44 24 00 59 c3 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}