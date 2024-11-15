
rule Trojan_MacOS_Amos_AI_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AI!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 13 eb 00 48 89 c3 48 8d bd 78 ff ff ff e8 f7 1e 00 00 eb 03 48 89 c3 48 8d bd 60 fe ff ff } //1
		$a_01_1 = {75 28 31 c0 48 81 c4 f8 00 00 00 5b 41 5c 41 5d 41 5e 41 5f 5d c3 8b 85 6c ff ff ff 04 07 88 45 9e 31 ff e8 87 17 00 00 0f 0b e8 7a 17 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}