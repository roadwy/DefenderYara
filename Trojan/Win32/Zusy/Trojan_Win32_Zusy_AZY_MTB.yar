
rule Trojan_Win32_Zusy_AZY_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 81 a8 7c 42 00 30 04 0a 83 e9 01 } //3
		$a_01_1 = {8a 8d c1 42 ff ff 32 8d c0 42 ff ff 80 c9 50 30 c1 88 8c 15 c0 42 ff ff 42 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
rule Trojan_Win32_Zusy_AZY_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.AZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c2 47 c1 e8 18 0f b6 0c 85 f0 bc 5e 00 0f b6 46 ff 8b 0c 8d f0 b0 5e 00 0f b6 04 85 f0 bc 5e 00 33 0c 85 f0 a8 5e 00 0f b6 c2 8b 56 02 0f b6 04 85 f0 bc 5e 00 33 0c 85 f0 a4 5e 00 0f b6 06 0f b6 04 85 f0 bc 5e 00 33 0c 85 f0 ac 5e 00 8b c2 c1 e8 18 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zusy_AZY_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.AZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {bf 02 9f f5 24 bb 16 27 1a 3f bd 2c 25 34 b6 8b 4c 24 24 81 f9 01 9f f5 24 7f 61 81 f9 6a d2 00 e1 0f 8e a7 00 00 00 81 f9 1d 08 72 f8 0f 8f 42 01 00 00 81 f9 6b d2 00 e1 0f 84 0a 02 00 00 81 f9 1f 1f dd e5 0f 84 3d 02 00 00 81 f9 38 08 97 f5 } //2
		$a_01_1 = {8b 4c 24 14 8a 54 24 0b 80 c2 34 88 54 01 30 8b 4c 24 14 8a 54 24 0b 80 c2 35 88 54 01 31 8b 0c 24 c7 01 1f 1f dd e5 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_Win32_Zusy_AZY_MTB_4{
	meta:
		description = "Trojan:Win32/Zusy.AZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 46 08 89 45 cc 8d 95 68 fe ff ff b8 64 89 4b 00 e8 2f f5 ff ff 8b 95 68 fe ff ff 8b 45 c4 e8 0d c3 f4 ff 75 02 b3 01 8d 95 64 fe ff ff b8 88 89 4b 00 e8 0d f5 ff ff 8b 95 64 fe ff ff 8b 45 c4 e8 eb c2 f4 ff 75 04 c6 45 fb 01 8d 95 60 fe ff ff b8 a4 89 4b 00 e8 e9 f4 ff ff 8b 95 60 fe ff ff 8b 45 c4 e8 c7 c2 f4 ff 75 04 c6 45 fa 01 8d 95 5c fe ff ff b8 c8 89 4b 00 } //2
		$a_01_1 = {30 31 39 46 39 41 32 37 37 41 35 31 44 45 32 38 35 37 38 37 43 46 33 43 37 37 } //1 019F9A277A51DE285787CF3C77
		$a_01_2 = {35 34 43 30 44 38 32 31 37 34 34 43 43 39 36 42 35 37 44 31 43 46 } //1 54C0D821744CC96B57D1CF
		$a_01_3 = {35 31 43 31 44 38 32 42 37 46 34 36 39 46 32 30 34 41 43 43 } //1 51C1D82B7F469F204ACC
		$a_01_4 = {35 30 43 38 43 33 32 30 36 37 34 31 43 33 32 41 34 35 44 41 43 46 33 36 33 43 34 36 43 39 32 30 } //1 50C8C3206741C32A45DACF363C46C920
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}