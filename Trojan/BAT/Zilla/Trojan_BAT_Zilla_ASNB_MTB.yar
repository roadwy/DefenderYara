
rule Trojan_BAT_Zilla_ASNB_MTB{
	meta:
		description = "Trojan:BAT/Zilla.ASNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 0b 16 0c 2b 1f 02 08 91 0d 08 1e 5d 13 04 03 11 04 9a 13 05 02 08 11 05 09 28 ?? ?? 00 06 b4 9c 08 17 d6 0c 08 07 31 dd 02 0a 2b 00 06 2a } //5
		$a_03_1 = {0a 03 6e 60 02 28 ?? 00 00 0a 66 03 66 d2 6e 60 5f b7 0a 2b 00 06 2a } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}