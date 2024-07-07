
rule Trojan_Win32_Guloader_SS_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {64 8b 1d c0 00 00 00 90 02 10 83 fb 00 0f 84 90 02 04 e9 90 00 } //1
		$a_03_1 = {0f 6e c0 0f 6e 0b 0f ef c1 51 90 02 10 0f 7e c1 88 c8 90 02 10 59 90 00 } //1
		$a_03_2 = {89 e0 83 c4 06 ff 28 e8 90 01 01 ff ff ff c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Guloader_SS_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0c 00 00 "
		
	strings :
		$a_03_0 = {0b 34 0a 66 0f 69 de 66 0f 68 e2 66 0f 6b cc 66 0f 63 de 0f 6a c2 0f 67 da 0f 69 c8 66 0f 68 e3 66 0f 68 f6 0f 6a ed 0f 6b ef 0f 68 f3 81 f6 90 01 04 66 0f 68 e8 0f 6b ca 0f 6a f5 0f 63 e2 0f 69 ee 0f 69 c9 0f 6b c0 0f 67 f9 66 0f 6a cc 66 0f 6b c8 0f 67 e3 0f 6a e8 0f 6b ef 0f 6a d7 0f 6b d9 89 34 08 90 00 } //5
		$a_00_1 = {0b 34 0a 0f 6b d7 66 0f 6b f6 66 0f 69 ce 66 0f 6a ce 0f 67 fe 66 0f 6b e9 0f 67 e7 0f 63 c4 66 0f 63 f8 81 f6 72 cd fb 07 0f 67 e1 0f 67 c9 66 0f 6b e0 0f 6a e0 0f 6a d0 66 0f 67 ea 0f 6a ff 0f 67 de 66 0f 63 c2 0f 6a e7 66 0f 63 d3 0f 68 d6 89 34 08 } //5
		$a_00_2 = {0b 34 0a 0f 69 e1 0f 63 ce 66 0f 67 d0 0f 6b e4 66 0f 69 f1 0f 67 cd 0f 6a f3 0f 68 d3 66 0f 6b ec 0f 69 e7 0f 67 e9 66 0f 63 c5 66 0f 6b e7 0f 68 f9 81 f6 9d 42 28 f1 66 0f 6a d8 0f 6b ce 0f 6a e5 66 0f 6b ec 66 0f 6b e7 66 0f 6a eb 66 0f 68 d7 66 0f 67 e7 0f 69 d3 0f 6a fc 66 0f 6b eb 0f 6b f5 89 34 08 } //5
		$a_01_3 = {52 00 65 00 6e 00 74 00 65 00 6e 00 69 00 76 00 65 00 61 00 75 00 37 00 } //1 Renteniveau7
		$a_01_4 = {70 00 65 00 72 00 69 00 63 00 61 00 72 00 64 00 69 00 6f 00 73 00 79 00 6d 00 70 00 68 00 79 00 73 00 69 00 73 00 } //1 pericardiosymphysis
		$a_01_5 = {4c 00 61 00 6e 00 67 00 6d 00 6f 00 64 00 69 00 67 00 68 00 65 00 64 00 65 00 6e 00 73 00 37 00 } //1 Langmodighedens7
		$a_01_6 = {4b 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 6f 00 6e 00 61 00 76 00 6e 00 73 00 32 00 } //1 Kommandonavns2
		$a_01_7 = {4e 00 6f 00 6e 00 65 00 6d 00 69 00 73 00 73 00 69 00 6f 00 6e 00 36 00 } //1 Nonemission6
		$a_01_8 = {53 00 6e 00 76 00 65 00 72 00 73 00 79 00 6e 00 65 00 64 00 65 00 73 00 37 00 } //1 Snversynedes7
		$a_01_9 = {56 00 65 00 6a 00 61 00 66 00 76 00 61 00 6e 00 64 00 69 00 6e 00 67 00 73 00 61 00 6e 00 6c 00 67 00 67 00 65 00 6e 00 65 00 39 00 } //1 Vejafvandingsanlggene9
		$a_01_10 = {46 00 65 00 6d 00 68 00 75 00 6e 00 64 00 72 00 65 00 64 00 6b 00 72 00 6f 00 6e 00 65 00 73 00 65 00 64 00 64 00 65 00 6c 00 65 00 6e 00 73 00 } //1 Femhundredkroneseddelens
		$a_01_11 = {49 00 6e 00 67 00 65 00 6e 00 69 00 72 00 67 00 65 00 72 00 6e 00 69 00 6e 00 67 00 65 00 72 00 73 00 33 00 } //1 Ingenirgerningers3
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=5
 
}
rule Trojan_Win32_Guloader_SS_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.SS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {bb a2 3b a3 41 0f 75 f3 66 0f fd f0 66 0f 60 cb 66 0f f5 f9 0f eb e1 66 0f fe c3 0f d8 e1 31 1c 24 0f dc c9 66 0f 69 c6 66 0f 76 c5 0f dd c3 66 0f e5 d5 66 0f db fb 8f 04 01 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}