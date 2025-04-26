
rule Trojan_Win64_IcedID_BM_MTB{
	meta:
		description = "Trojan:Win64/IcedID.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 36 4c 32 73 4a 4b } //1 C6L2sJK
		$a_01_1 = {46 56 69 36 68 31 } //1 FVi6h1
		$a_01_2 = {52 75 6e 4f 62 6a 65 63 74 } //1 RunObject
		$a_01_3 = {5a 36 35 50 64 53 74 } //1 Z65PdSt
		$a_01_4 = {61 36 57 44 48 72 66 73 61 36 } //1 a6WDHrfsa6
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_BM_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 79 6b 49 72 78 6c 57 67 53 } //1 AykIrxlWgS
		$a_01_1 = {49 39 51 57 46 34 45 } //1 I9QWF4E
		$a_01_2 = {4d 34 59 50 44 51 6e } //1 M4YPDQn
		$a_01_3 = {50 67 5a 74 55 49 77 4c 32 39 } //1 PgZtUIwL29
		$a_01_4 = {50 6e 33 5a 5a 68 } //1 Pn3ZZh
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_BM_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 50 6d 7a 44 42 4c 71 42 76 } //1 BPmzDBLqBv
		$a_01_1 = {42 79 73 41 62 39 67 52 4f 48 } //1 BysAb9gROH
		$a_01_2 = {49 42 70 6c 76 36 } //1 IBplv6
		$a_01_3 = {50 6c 75 67 69 6e 49 6e 69 74 } //1 PluginInit
		$a_01_4 = {51 36 79 59 51 45 76 68 } //1 Q6yYQEvh
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_BM_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {e6 19 48 f7 f2 48 c1 ef 3d 48 81 e3 b6 1b 00 00 e4 b0 49 81 e8 c7 0a 00 00 4c 0b c0 48 81 dc 8b 21 00 00 48 81 ea ca 17 00 00 48 ff cd e4 de e6 ff 49 81 cf 98 22 00 00 48 f7 f8 41 59 } //3
		$a_01_1 = {49 46 50 47 70 78 58 61 } //1 IFPGpxXa
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}
rule Trojan_Win64_IcedID_BM_MTB_5{
	meta:
		description = "Trojan:Win64/IcedID.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b f8 eb 2c 48 8d 8c 24 ?? ?? ?? ?? ff 54 24 ?? eb 14 48 8d 84 24 ?? ?? ?? ?? 48 8b f8 eb 20 83 c1 14 f3 a4 eb 31 48 81 c4 ?? ?? ?? ?? 5f eb } //1
		$a_00_1 = {79 67 75 61 73 64 68 75 61 73 79 64 67 74 61 76 73 79 64 79 61 73 64 61 6b 6a 61 } //1 yguasdhuasydgtavsydyasdakja
		$a_00_2 = {72 71 64 61 6b 63 2e 64 6c 6c } //1 rqdakc.dll
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}