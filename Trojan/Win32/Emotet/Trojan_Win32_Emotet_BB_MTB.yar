
rule Trojan_Win32_Emotet_BB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d1 8b 4c 24 90 01 01 03 d0 8d 04 09 2b d0 8b 44 24 90 01 01 03 d5 8a 18 8a 0c 3a 32 d9 8b 4c 24 90 01 01 88 18 8b 44 24 90 01 01 40 3b c1 89 44 24 90 01 01 0f 82 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Emotet_BB_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 6c 24 1c 8b 5c 24 20 03 c6 57 8b 7c 24 28 8d 04 40 c7 44 24 14 00 00 00 00 2b c7 03 c5 8d 5c 18 05 8d 41 01 } //10
		$a_01_1 = {6c 23 23 42 2b 6b 26 72 42 24 63 62 5e 41 48 61 35 34 25 2a 6f 44 71 65 45 75 73 6b 46 6e 38 56 68 40 56 34 6c } //3 l##B+k&rB$cb^AHa54%*oDqeEuskFn8Vh@V4l
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*3) >=13
 
}
rule Trojan_Win32_Emotet_BB_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.BB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 8b 84 85 f0 f9 ff ff 8b 8d ec f9 ff ff 03 84 8d f0 f9 ff ff 99 b9 81 01 00 00 f7 f9 8b 45 08 03 45 f8 0f b6 08 33 8c 95 f0 f9 ff ff 8b 55 08 03 55 f8 88 0a e9 } //1
		$a_01_1 = {8a 44 8c 10 8b da 8b 54 9c 10 89 54 8c 10 0f b6 d0 89 54 9c 10 8b 44 8c 10 03 c2 99 f7 ff 0f b6 44 94 10 30 44 2e ff 3b b4 24 9c 08 00 00 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}