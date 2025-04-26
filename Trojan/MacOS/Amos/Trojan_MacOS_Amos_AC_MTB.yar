
rule Trojan_MacOS_Amos_AC_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AC!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 d2 89 b4 94 60 01 00 00 41 0f b6 94 0c 4b 8f 00 00 8b b4 94 60 01 00 00 ff c6 ?? ?? 89 b4 94 60 01 00 00 41 0f b6 94 0c 4c 8f 00 00 8b b4 94 60 01 00 00 ff c6 ?? ?? 89 b4 94 60 01 00 00 48 81 f9 1d 01 00 00 ?? ?? 41 0f b6 94 0c 4d 8f 00 00 8b b4 94 60 01 00 00 48 83 c1 03 ff c6 ?? ?? 67 0f b9 } //1
		$a_02_1 = {74 36 49 8b 45 f0 48 39 d8 ?? ?? 48 8d 68 e8 f6 40 e8 01 ?? ?? 48 8b 78 f8 e8 ed 03 00 00 48 89 e8 48 39 dd ?? ?? 49 8b 3c 24 ?? ?? 48 89 df 49 89 5d f0 e8 d3 03 00 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}