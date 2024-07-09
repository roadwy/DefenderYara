
rule Trojan_Win32_Spycos_H{
	meta:
		description = "Trojan:Win32/Spycos.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 45 e4 3b 7d ec 7d 03 47 eb 05 bf 01 00 00 00 8b 45 f4 0f b6 5c 38 ff 33 5d e4 3b 5d e8 7f 0b 81 c3 ff 00 00 00 2b 5d e8 eb 03 2b 5d e8 8d 45 d0 8b d3 e8 ?? ?? ?? ff 8b 55 d0 8d 45 f8 e8 ?? ?? ?? ff 8b 45 e4 89 45 e8 83 c6 02 8b 45 fc } //1
		$a_00_1 = {00 43 6f 6e 74 72 6f 6c 50 61 6e 65 6c 43 70 6c 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00 00 } //1
		$a_00_2 = {00 6d 6d 79 79 79 79 00 00 ff ff ff ff 04 00 00 00 2e 73 71 6d 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Spycos_H_2{
	meta:
		description = "Trojan:Win32/Spycos.H,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 43 6f 6e 74 72 6f 6c 50 61 6e 65 6c 43 70 6c 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}