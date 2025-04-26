
rule Trojan_MacOS_Amos_BT_MTB{
	meta:
		description = "Trojan:MacOS/Amos.BT!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 48 89 e5 53 50 48 89 fb 48 8b 07 48 8b 78 e8 48 01 df 6a 0a 5e e8 ?? ?? ?? ?? 0f be f0 48 89 df e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 48 89 d8 48 83 c4 08 5b 5d c3 } //1
		$a_03_1 = {48 8d bd 60 ff ff ff e8 ?? ?? ?? ?? 48 8d bd 48 ff ff ff e8 ?? ?? ?? ?? 48 8d 7d a8 e8 ?? ?? ?? ?? 31 c0 48 81 c4 b0 00 00 00 5b 41 5e 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}