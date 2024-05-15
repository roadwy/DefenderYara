
rule Trojan_Win32_Ulise_AI_MTB{
	meta:
		description = "Trojan:Win32/Ulise.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {ff 75 35 e8 90 01 04 05 50 c3 00 00 33 d2 89 45 d8 89 55 dc e8 90 01 04 33 d2 3b 55 90 00 } //05 00 
		$a_03_1 = {2a 18 30 8a 90 01 04 14 70 b2 62 7b 90 00 } //01 00 
		$a_01_2 = {5a 36 be f4 9d e5 99 b9 df 59 74 a7 bf 43 ce 61 b9 b5 e1 } //01 00 
		$a_01_3 = {73 68 65 6e 68 75 61 2e 64 6c 6c } //00 00  shenhua.dll
	condition:
		any of ($a_*)
 
}