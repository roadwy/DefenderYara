
rule Trojan_Win32_Lazy_HNB_MTB{
	meta:
		description = "Trojan:Win32/Lazy.HNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {85 c0 74 09 6a 04 8d 4d f8 51 56 ff d0 8d 45 fc 50 ff 75 fc 6a 04 56 ff 15 ?? ?? ?? ?? 5e 8b e5 5d c3 } //2
		$a_01_1 = {8b 06 a3 00 30 00 10 a1 04 30 00 10 c7 45 f8 00 10 00 10 } //2
		$a_03_2 = {46 77 70 6d 46 72 65 65 4d 65 6d 6f 72 79 30 00 66 77 70 75 63 6c 6e 74 2e 64 6c 6c ?? ?? ?? ?? 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 ?? ?? ?? ?? 44 69 73 61 62 6c 65 54 68 72 65 61 64 4c 69 62 72 61 72 79 43 61 6c 6c 73 ?? ?? ?? 47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 41 ?? ?? ?? ?? 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 ?? ?? 4b 45 52 4e 45 4c 33 32 2e 64 6c 6c } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2) >=6
 
}