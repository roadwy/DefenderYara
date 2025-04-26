
rule Trojan_Win64_Ulise_NS_MTB{
	meta:
		description = "Trojan:Win64/Ulise.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 8b 08 48 89 4a 18 48 8b 00 48 89 45 f8 48 83 f8 00 0f 84 ?? ?? ?? ?? 48 8b 45 f8 48 8b 4d d8 48 89 48 20 48 8b 45 d0 } //3
		$a_01_1 = {48 8b 45 d0 48 8b 55 d8 48 83 c4 20 4c 8b 01 4c 89 45 e0 48 8b 49 08 48 89 4d e8 48 c7 42 20 00 00 00 00 48 05 68 08 00 00 49 c1 e0 08 4c 01 c0 48 c1 e1 03 48 01 c8 } //2
		$a_01_2 = {52 65 67 51 75 65 72 79 49 6e 66 6f 4b 65 79 57 } //1 RegQueryInfoKeyW
		$a_01_3 = {53 6c 65 65 70 43 6f 6e 64 69 74 69 6f 6e 56 61 72 69 61 62 6c 65 } //1 SleepConditionVariable
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}