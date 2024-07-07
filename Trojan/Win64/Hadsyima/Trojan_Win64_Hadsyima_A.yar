
rule Trojan_Win64_Hadsyima_A{
	meta:
		description = "Trojan:Win64/Hadsyima.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 70 75 69 64 73 64 6b 2e 64 6c 6c 00 51 75 65 72 79 49 6e 74 65 72 66 61 63 65 } //1
		$a_01_1 = {66 ad 48 0f b7 c8 c1 e9 0c 66 25 ff 0f 48 85 c9 74 0b 48 0f b7 c9 f3 a4 48 03 f0 eb e3 } //1
		$a_03_2 = {58 48 0f b7 c8 48 8d 88 00 03 00 00 c7 01 90 01 04 c7 41 04 90 01 04 65 48 8b 14 25 60 00 00 00 48 89 51 08 48 8b d3 ff d0 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}