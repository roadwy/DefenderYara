
rule Trojan_Win64_Zusy_ASG_MTB{
	meta:
		description = "Trojan:Win64/Zusy.ASG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_03_0 = {f6 da 1b d2 83 c2 02 ff 15 ?? ?? 00 00 49 8b 4e 18 4c 8b e0 66 89 7c 24 30 0f b7 09 ff 15 ?? ?? 00 00 49 8b 0e 66 89 44 24 32 48 8b 09 ff 15 ?? ?? 00 00 44 8d 43 10 49 8b cc 48 8d 54 24 30 89 44 24 34 ff 15 } //2
		$a_03_1 = {48 8b c8 ff 15 ?? ?? 00 00 48 8d 05 ?? ?? 00 00 48 89 44 24 48 48 c7 44 24 58 87 69 00 00 c6 44 24 40 00 48 c7 44 24 50 00 04 00 00 b9 02 01 00 00 48 8d 94 24 30 01 00 00 ff 15 ?? ?? 00 00 48 8b 4c 24 48 ff 15 ?? ?? 00 00 48 8b d8 48 85 c0 } //2
		$a_03_2 = {48 8b c8 ff 15 ?? ?? 00 00 48 8d 15 ?? ?? 00 00 48 89 54 24 50 48 c7 44 24 ?? 87 69 00 00 c6 44 24 40 00 48 c7 44 24 68 00 04 00 00 48 8b ?? ?? 20 00 00 e8 ?? ?? ff ff 48 8d 15 ?? ?? ff ff 48 8b c8 ff 15 ?? ?? 00 00 b9 02 01 00 00 48 8d 55 30 ff 15 ?? ?? 00 00 48 8b 4c 24 50 ff 15 ?? ?? 00 00 48 8b d8 48 85 c0 } //2
		$a_03_3 = {48 8b c8 ff 15 ?? ?? 00 00 48 8d 05 ?? ?? 00 00 48 89 44 24 58 48 c7 44 24 70 87 69 00 00 c6 44 24 50 00 48 c7 44 24 68 00 04 00 00 b9 02 02 00 00 48 8d 55 40 ff 15 ?? ?? 00 00 48 8b 4c 24 58 ff 15 ?? ?? 00 00 48 8b d8 48 85 c0 } //2
		$a_03_4 = {48 2b e0 48 8b 05 ?? ?? 00 00 48 33 c4 48 89 84 24 70 15 00 00 48 8b f1 48 8d 54 24 40 b9 01 01 00 00 ff 15 ?? ?? 00 00 bb 02 00 00 00 8b d3 8b cb 44 8d 43 0f ff 15 ?? ?? 00 00 48 8b 4e 18 4c 8b e0 66 89 5c 24 30 0f b7 09 ff 15 ?? ?? 00 00 48 8b 0e 66 89 44 24 32 48 8b 09 ff 15 ?? ?? 00 00 89 44 24 34 44 8d 43 0e 48 8d 54 24 30 49 8b cc 33 c0 48 89 44 24 38 ff 15 ?? ?? 00 00 e8 } //2
		$a_01_5 = {53 65 6e 64 20 66 61 69 6c 75 72 65 } //1 Send failure
		$a_01_6 = {43 61 6e 27 74 20 63 6f 6e 6e 65 63 74 21 } //1 Can't connect!
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2+(#a_03_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}