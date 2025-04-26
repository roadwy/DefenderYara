
rule Trojan_MacOS_Amos_CI_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CI!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 48 89 e5 41 56 53 49 89 fe bf 10 00 00 00 e8 ?? ?? ?? ?? 48 89 c3 48 89 c7 4c 89 f6 e8 ?? ?? ?? ?? 48 8b 35 df c7 00 00 48 8b 15 c0 c7 00 00 48 89 df } //1
		$a_03_1 = {4c 89 ff e8 ?? ?? ?? ?? 4c 89 f7 e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 31 c0 48 81 c4 c0 00 00 00 5b 41 5c 41 5e 41 5f 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}