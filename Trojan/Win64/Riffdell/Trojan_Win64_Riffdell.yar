
rule Trojan_Win64_Riffdell{
	meta:
		description = "Trojan:Win64/Riffdell,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 06 00 00 "
		
	strings :
		$a_03_0 = {0f 01 11 0f 01 59 0a 0f 00 51 14 48 8d 15 ?? ?? ?? ?? 48 0f b7 41 16 50 52 48 cb } //1
		$a_01_1 = {8e 59 18 8e 41 1a 8e 61 1c 8e 69 1e 8e 51 20 c3 } //1
		$a_01_2 = {40 53 48 83 ec 20 8b 51 30 44 8b 41 34 48 8b 5c 0a 10 48 8b 44 0a 1c 0f 22 d8 44 2b c2 41 83 f8 38 74 10 48 83 c1 24 48 8d 05 a2 ff ff ff 48 03 ca ff d0 } //1
		$a_01_3 = {36 37 62 65 65 38 62 38 2d 36 38 38 36 2d 34 65 38 35 2d 62 35 64 63 2d 33 34 32 31 62 34 63 34 64 66 39 32 } //10 67bee8b8-6886-4e85-b5dc-3421b4c4df92
		$a_01_4 = {63 62 61 32 39 64 64 62 2d 65 62 65 36 2d 34 64 35 36 2d 39 62 38 34 2d 34 32 66 63 66 38 61 64 65 61 65 62 } //10 cba29ddb-ebe6-4d56-9b84-42fcf8adeaeb
		$a_01_5 = {65 33 64 37 61 38 65 65 2d 34 66 65 33 2d 34 37 30 66 2d 61 36 32 66 2d 30 37 34 65 38 65 33 36 30 30 38 32 } //10 e3d7a8ee-4fe3-470f-a62f-074e8e360082
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10) >=33
 
}