
rule Trojan_MacOS_Amos_AU_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AU!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 48 89 e5 48 83 ec 20 48 89 7d f8 48 89 75 f0 48 8b 7d f8 48 89 7d e8 48 8b 45 f0 88 45 e7 e8 fc ?? ?? ?? 8a 55 e7 48 8b 7d e8 8a 08 80 e2 7f c0 e2 01 80 e1 01 08 d1 88 08 e8 e1 ?? ?? ?? 8a 08 80 e1 fe 80 c9 00 88 08 48 83 c4 20 } //1
		$a_03_1 = {48 8b 45 f0 48 3b 45 e8 0f 84 ?? ?? ?? ?? 48 8b 7d c0 48 8b 75 f0 e8 e5 ?? ?? ?? 48 8b 45 f0 48 83 c0 01 48 89 45 f0 48 8b 45 c0 48 83 c0 01 48 89 45 c0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}