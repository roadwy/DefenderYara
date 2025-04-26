
rule Trojan_Win32_Lazy_HNS_MTB{
	meta:
		description = "Trojan:Win32/Lazy.HNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 00 00 01 00 43 6c 61 73 73 69 63 45 78 70 6c 6f 72 65 72 33 32 5f 64 6c 6c 2e 64 6c 6c 00 44 6c 6c 45 78 70 6f 72 74 53 65 74 74 69 6e 67 73 58 6d 6c 00 53 68 6f 77 45 78 70 6c 6f 72 65 72 53 65 74 74 69 6e 67 73 00 } //2
		$a_03_1 = {85 c0 78 0d 8b 40 ?? 8b 40 ?? 8b 00 8b 00 8b 40 ?? c3 } //2
		$a_03_2 = {8b c3 0f ac c1 ?? 0f b7 f1 33 c9 85 f6 74 1a 0f be 14 0b c1 cf ?? 80 3c 0b } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=6
 
}