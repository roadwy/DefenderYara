
rule Trojan_Win64_Sirefef_F{
	meta:
		description = "Trojan:Win64/Sirefef.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 54 48 8b f8 49 8b f4 f3 a4 0f b7 55 14 44 0f b7 4d 06 4c 8d 44 2a 24 41 8b 00 41 8b 48 fc 49 83 c0 28 41 83 c1 ff 4a 8d 34 20 48 8d 3c 18 f3 a4 75 e5 } //3
		$a_01_1 = {78 36 34 5c 72 65 6c 65 61 73 65 5c 49 4e 42 52 36 34 } //1 x64\release\INBR64
		$a_01_2 = {5c 00 55 00 5c 00 25 00 30 00 38 00 78 00 2e 00 40 00 } //1 \U\%08x.@
		$a_01_3 = {25 00 73 00 55 00 5c 00 25 00 30 00 38 00 78 00 2e 00 40 00 } //1 %sU\%08x.@
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win64_Sirefef_F_2{
	meta:
		description = "Trojan:Win64/Sirefef.F,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 54 48 8b f8 49 8b f4 f3 a4 0f b7 55 14 44 0f b7 4d 06 4c 8d 44 2a 24 41 8b 00 41 8b 48 fc 49 83 c0 28 41 83 c1 ff 4a 8d 34 20 48 8d 3c 18 f3 a4 75 e5 } //2
		$a_01_1 = {78 36 34 5c 72 65 6c 65 61 73 65 5c 49 4e 42 52 36 34 } //1 x64\release\INBR64
		$a_01_2 = {5c 00 55 00 5c 00 25 00 30 00 38 00 78 00 2e 00 40 00 } //1 \U\%08x.@
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}