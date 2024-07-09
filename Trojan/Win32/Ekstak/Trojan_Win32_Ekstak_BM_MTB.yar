
rule Trojan_Win32_Ekstak_BM_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b e8 8b 4c 24 28 55 83 c1 04 89 4c 24 2c 8d 4c 24 20 51 53 ff 15 ?? ?? 65 00 55 ff 15 ?? ?? 65 00 8b 4c 24 20 83 c1 04 3b cf } //1
		$a_01_1 = {70 00 62 00 38 00 32 00 35 00 } //1 pb825
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}