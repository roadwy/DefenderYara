
rule Trojan_Win64_Donipye_STH{
	meta:
		description = "Trojan:Win64/Donipye.STH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {41 88 3c 08 48 ff c1 48 c1 ff 08 ff cb 4c 39 c9 0f 8d ?? ?? 00 00 84 db 75 } //1
		$a_03_1 = {48 b8 01 23 45 67 89 ab cd ef 48 89 ?? ?? ?? ?? ?? ?? 48 b8 fe dc ba 98 76 54 32 10 48 89 } //1
		$a_03_2 = {14 84 d7 17 48 ?? ?? ?? ?? 14 84 d7 17 e8 } //1
		$a_00_3 = {2f 43 4c 52 57 72 61 70 70 65 72 2e 67 6f } //1 /CLRWrapper.go
		$a_01_4 = {43 63 32 6b 3d 0a f9 32 43 31 86 18 20 72 00 82 42 10 41 16 d8 f2 48 34 73 49 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}