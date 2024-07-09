
rule Trojan_Win64_IcedID_SD_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 7c 41 b9 04 00 00 00 41 b8 00 30 00 00 8b d0 33 c9 ff 94 24 } //1
		$a_03_1 = {48 8b c1 0f b6 44 04 ?? 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1 48 63 4c 24 ?? 48 8b 54 24 ?? 88 04 0a e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win64_IcedID_SD_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 8d 04 16 83 e2 ?? 41 83 e0 ?? 8a 44 94 ?? 42 02 44 84 ?? 41 32 04 3b 41 88 04 0b 4c 03 de 42 8b 4c 84 ?? 8b 44 94 ?? 83 e1 ?? d3 c8 ff c0 89 44 94 } //1
		$a_00_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}