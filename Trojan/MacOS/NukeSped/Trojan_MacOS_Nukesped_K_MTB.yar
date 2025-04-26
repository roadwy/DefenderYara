
rule Trojan_MacOS_Nukesped_K_MTB{
	meta:
		description = "Trojan:MacOS/Nukesped.K!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 48 89 e5 48 83 ec 10 48 89 7d f8 48 8b 7f 08 e8 ?? ?? ?? ?? 48 8b 7d f8 48 8b 7f 10 ff ?? ?? ?? ?? ?? 48 8b 45 f8 48 83 c4 10 5d c3 } //1
		$a_03_1 = {48 89 45 f8 75 ?? 48 8b 3d d0 69 00 00 e8 ?? ?? ?? ?? 48 89 c7 e8 ?? ?? ?? ?? 48 89 c1 48 89 c8 48 89 0d f6 6c 00 00 48 89 45 f8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}