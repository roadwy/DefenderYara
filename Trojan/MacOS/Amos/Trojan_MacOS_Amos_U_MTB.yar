
rule Trojan_MacOS_Amos_U_MTB{
	meta:
		description = "Trojan:MacOS/Amos.U!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 4d d0 30 4c 05 d0 48 ff c0 48 83 f8 04 75 ?? 44 0f b6 23 41 f6 c4 01 48 89 7d c8 74 ?? 4c 8b 73 10 } //1
		$a_03_1 = {48 8b 85 88 d2 ff ff 48 85 c0 0f ?? ?? ?? ?? ?? f3 48 0f 2a c0 e9 ?? ?? ?? ?? 4c 39 f1 72 ?? 48 89 c8 31 d2 49 f7 f6 48 89 d1 48 8b 85 70 d2 ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}