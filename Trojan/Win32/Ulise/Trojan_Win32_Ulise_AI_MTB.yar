
rule Trojan_Win32_Ulise_AI_MTB{
	meta:
		description = "Trojan:Win32/Ulise.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff 75 35 e8 ?? ?? ?? ?? 05 50 c3 00 00 33 d2 89 45 d8 89 55 dc e8 ?? ?? ?? ?? 33 d2 3b 55 } //5
		$a_03_1 = {2a 18 30 8a ?? ?? ?? ?? 14 70 b2 62 7b } //5
		$a_01_2 = {5a 36 be f4 9d e5 99 b9 df 59 74 a7 bf 43 ce 61 b9 b5 e1 } //1
		$a_01_3 = {73 68 65 6e 68 75 61 2e 64 6c 6c } //1 shenhua.dll
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}