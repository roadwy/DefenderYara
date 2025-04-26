
rule Trojan_Win32_QbotCore_B_MTB{
	meta:
		description = "Trojan:Win32/QbotCore.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 } //1
		$a_00_1 = {48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 f1 4c 03 4c 24 08 45 39 d1 } //1
		$a_02_2 = {8b c2 83 e0 0f 8a ?? ?? ?? ?? ?? 8d 0c 3a 32 04 0e 42 88 01 3b 55 0c 72 e7 5e } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}