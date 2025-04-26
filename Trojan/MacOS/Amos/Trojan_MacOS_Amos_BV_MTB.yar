
rule Trojan_MacOS_Amos_BV_MTB{
	meta:
		description = "Trojan:MacOS/Amos.BV!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 7d e0 48 89 47 08 48 89 07 48 8b 07 48 8b 4d f0 48 c1 e1 02 48 01 c8 48 89 45 d8 e8 ?? ?? ?? ?? 48 8b 4d d8 48 8b 7d e0 48 89 08 31 c0 89 c6 e8 ?? ?? ?? ?? 48 83 c4 30 5d c3 } //1
		$a_03_1 = {55 48 89 e5 48 83 ec 20 89 7d fc 48 89 75 f0 8b 7d fc e8 ?? ?? ?? ?? 83 f8 00 0f ?? ?? ?? ?? ?? 48 63 4d fc 48 8b 05 ad 9f 00 00 8b 44 88 3c 48 23 45 f0 48 83 f8 00 0f 95 c0 34 ff 34 ff 88 45 ef } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}