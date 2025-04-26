
rule Trojan_Win64_CymulateRansomTest_MKC_MTB{
	meta:
		description = "Trojan:Win64/CymulateRansomTest.MKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {45 30 01 4c 8b 49 ?? 41 0f b6 41 ?? 44 0f b6 44 08 ?? 45 30 41 ?? 41 b9 ?? ?? ?? ?? 4c 8b 41 ?? 41 0f b6 40 ?? 0f b6 54 08 ?? 41 30 50 ?? 4c 8b 41 ?? 41 0f b6 40 ?? 0f b6 54 08 ?? 41 0f b6 c2 41 30 50 ?? 45 02 d2 c0 e8 07 0f b6 c0 6b d0 ?? 41 32 d2 41 b2 ?? 41 88 13 } //1
		$a_03_1 = {41 0f b6 c2 41 80 c2 04 4e 8d 04 0a 0f b6 54 10 ?? 41 30 50 ?? 48 8b 41 18 4a 8d 14 08 42 0f b6 44 08 ?? 30 02 48 8b 41 ?? 49 8d 14 01 41 0f b6 44 01 ?? 30 42 ?? 48 8b 41 ?? 49 8d 14 01 41 0f b6 44 01 ?? 30 42 02 4d 8d 49 04 41 80 fa ?? 72 } //1
		$a_01_2 = {5c 55 73 65 72 73 5c 59 6f 61 76 53 68 61 68 61 72 61 62 61 6e 69 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 77 69 6e 64 6f 77 73 2d 73 63 65 6e 61 72 69 6f 73 5c 50 61 79 6c 6f 61 64 73 5c 4e 61 74 69 76 65 52 61 6e 73 6f 6d 65 77 61 72 65 44 6c 6c 5c 78 36 34 5c 52 61 6e 64 6f 6d 4b 65 79 5f 4d 61 6e 75 61 6c 41 65 73 5f 4f 76 65 72 77 72 69 74 65 5c 4e 61 74 69 76 65 52 61 6e 73 6f 6d 65 77 61 72 65 44 6c 6c 2e 70 64 62 } //1 \Users\YoavShaharabani\source\repos\windows-scenarios\Payloads\NativeRansomewareDll\x64\RandomKey_ManualAes_Overwrite\NativeRansomewareDll.pdb
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}