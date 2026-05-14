
rule Trojan_Win32_Babar_ABR_MTB{
	meta:
		description = "Trojan:Win32/Babar.ABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 68 00 a0 00 00 8d 85 f4 5f ff ff 50 8b 45 fc 50 } //1
		$a_01_1 = {83 c0 40 8d 95 f4 5f ff ff e8 17 c3 ed ff 8b 85 f0 5f ff ff 33 d2 89 50 3c 8b 85 f0 5f ff ff 33 d2 89 50 44 8b 85 f0 5f ff ff 33 d2 89 50 48 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Babar_ABR_MTB_2{
	meta:
		description = "Trojan:Win32/Babar.ABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c9 66 89 8d 20 f9 ff ff c7 85 1c f9 ff ff 01 00 00 00 89 9d 34 f9 ff ff 33 c0 89 85 38 f9 ff ff 89 85 3c f9 ff ff 89 85 40 f9 ff ff 8d 95 34 f9 ff ff 52 8d 85 f0 f8 ff ff 50 53 53 68 00 00 00 08 53 53 53 8d 8d 48 f9 ff ff 51 8d 95 58 fd ff ff 52 } //2
		$a_01_1 = {0f b6 71 fe 8b de c1 eb 04 0f b6 9b 54 67 42 00 88 18 83 e6 0f 0f b6 9e 54 67 42 00 88 58 01 0f b6 71 ff 8b de c1 eb 04 0f b6 9b 54 67 42 00 88 58 02 83 e6 0f 0f b6 9e 54 67 42 00 88 58 03 0f b6 31 8b de c1 eb 04 0f b6 9b 54 67 42 00 88 58 04 83 e6 0f 0f b6 9e 54 67 42 00 88 58 05 0f b6 71 01 8b de c1 eb 04 0f b6 9b 54 67 42 00 88 58 06 83 e6 0f 0f b6 9e 54 67 42 00 88 58 07 83 c0 08 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}