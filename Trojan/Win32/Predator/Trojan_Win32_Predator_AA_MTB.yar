
rule Trojan_Win32_Predator_AA_MTB{
	meta:
		description = "Trojan:Win32/Predator.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 63 72 65 65 6e 73 68 6f 74 2e 6a 70 65 67 } //1 Screenshot.jpeg
		$a_00_1 = {5c 46 6f 78 6d 61 69 6c 2e 75 72 6c 2e 6d 61 } //1 \Foxmail.url.ma
		$a_00_2 = {42 63 72 79 70 74 2e 64 6c 6c } //1 Bcrypt.dll
		$a_02_3 = {0f b6 04 0f 33 c6 c1 ee 08 0f b6 c0 33 34 85 ?? ?? ?? ?? 47 3b fa 72 e8 f7 d6 5f 8b c6 5e c3 } //1
		$a_00_4 = {30 4c 05 f5 40 83 f8 0a 73 05 8a 4d f4 eb f1 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}