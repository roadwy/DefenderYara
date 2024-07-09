
rule Trojan_WinNT_Alureon_AB{
	meta:
		description = "Trojan:WinNT/Alureon.AB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 3f 00 3f 00 5c 00 70 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 64 00 72 00 69 00 76 00 65 00 25 00 64 00 } //1 \??\physicaldrive%d
		$a_00_1 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6b 00 64 00 63 00 6f 00 6d 00 2e 00 64 00 6c 00 6c 00 } //1 \systemroot\system32\kdcom.dll
		$a_03_2 = {3b 46 18 0f 82 ?? ?? ff ff 83 45 ?? 04 ff 4d ?? 0f 85 ?? ?? ff ff ff 4d ?? 0f 85 fb fe ff ff 8b 45 ?? 8b 55 08 8b 4d ?? 89 50 18 8b 71 58 89 70 40 8b 71 28 03 f2 5f 89 70 1c 8b 49 08 5e 89 48 44 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}