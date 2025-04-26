
rule Trojan_MacOS_Amos_BX_MTB{
	meta:
		description = "Trojan:MacOS/Amos.BX!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 89 ff e8 ?? ?? ?? ?? 4c 89 f7 e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 31 c0 48 81 c4 a8 00 00 00 5b 41 5c 41 5d 41 5e 41 5f 5d c3 } //1
		$a_01_1 = {0f b6 3c 10 41 89 14 b9 0f b6 7c 10 01 44 8d 42 01 45 89 04 b9 0f b6 7c 10 02 44 8d 42 02 45 89 04 b9 0f b6 7c 10 03 44 8d 42 03 45 89 04 b9 48 83 c2 04 48 39 f2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}