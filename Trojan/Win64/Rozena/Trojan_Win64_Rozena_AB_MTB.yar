
rule Trojan_Win64_Rozena_AB_MTB{
	meta:
		description = "Trojan:Win64/Rozena.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 27 00 00 00 48 89 c7 48 89 d6 f3 48 a5 48 89 f2 48 89 f8 0f b7 0a 66 89 08 48 b8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Rozena_AB_MTB_2{
	meta:
		description = "Trojan:Win64/Rozena.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {33 ed 89 6c 24 20 45 33 c9 45 33 c0 ba 01 00 00 00 48 8d 0d f6 66 03 00 ff 15 ?? 92 02 00 48 8b f8 48 85 c0 75 3c 48 8d 15 49 67 03 00 48 8d 0d 22 d5 03 00 e8 8d 09 00 00 48 8b d8 ff 15 [0-02] 02 00 8b d0 48 8b cb e8 9a 10 00 00 48 8b c8 48 8d 15 1c 67 03 00 e8 6b 09 00 00 b0 01 e9 f0 07 00 00 48 89 6c 24 28 c7 44 24 20 00 00 00 04 45 33 c9 45 33 c0 48 8d 15 aa 66 03 00 48 8b cf ff 15 ?? 92 02 00 48 8b d8 48 85 c0 75 45 } //6
		$a_03_1 = {e9 8e 06 00 00 48 63 71 3c 48 03 f1 48 89 b4 24 c8 10 00 00 8b 56 50 33 c9 41 b9 04 00 00 00 41 b8 00 30 00 00 ff 15 [0-02] 02 00 4c 8b f8 48 85 c0 75 21 40 32 ff 48 8d 05 96 d3 03 00 48 8d 2d 07 66 03 00 48 8b d5 48 8b c8 } //6
		$a_01_2 = {5b 49 4e 46 4f 5d 20 4c 6f 61 64 69 6e 67 20 50 45 20 69 6e 20 6d 65 6d 6f 72 79 2e 2e 2e } //2 [INFO] Loading PE in memory...
		$a_01_3 = {5b 2d 5d 20 46 61 69 6c 65 64 20 74 6f 20 64 6f 77 6e 6c 6f 61 64 20 64 61 74 61 2e } //2 [-] Failed to download data.
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*6+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=16
 
}