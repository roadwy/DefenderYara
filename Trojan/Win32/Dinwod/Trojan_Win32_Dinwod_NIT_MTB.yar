
rule Trojan_Win32_Dinwod_NIT_MTB{
	meta:
		description = "Trojan:Win32/Dinwod.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 04 56 68 a0 77 40 00 6a 00 6a 00 ff 15 78 32 43 00 6a 01 50 89 46 64 ff 15 74 32 43 00 8b 46 64 50 ff 15 70 32 43 00 5f 5e 83 c4 08 c2 04 00 cc 8b 46 60 83 ec 1c 85 c0 74 07 50 ff 15 6c 32 43 00 8b 46 64 57 8b 3d 7c 32 43 00 68 e8 03 00 00 50 ff d7 85 c0 } //2
		$a_01_1 = {50 89 74 24 40 e8 63 62 01 00 83 c4 0c 68 20 71 43 00 ff 15 60 32 43 00 8b d8 3b de 89 5c 24 24 0f 84 d6 01 00 00 8b 35 5c 32 43 00 68 30 71 43 00 53 ff d6 68 4c 71 43 00 53 8b f8 ff d6 68 5c 71 43 00 53 8b e8 ff d6 85 c0 89 44 24 30 0f 84 a1 01 00 00 85 ed 0f 84 99 01 00 00 85 ff 0f 84 91 01 00 00 6a 00 6a 02 ff d7 8b f0 83 fe ff 89 74 24 20 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}