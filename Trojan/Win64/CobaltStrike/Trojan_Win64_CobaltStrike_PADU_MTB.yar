
rule Trojan_Win64_CobaltStrike_PADU_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PADU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 45 fc 00 00 00 00 8b 45 f8 48 63 d0 48 8b 45 10 48 01 d0 44 0f b6 00 8b 45 fc 48 63 d0 48 8b 45 20 48 01 d0 0f b6 08 8b 45 f8 48 63 d0 48 8b 45 10 48 01 d0 44 89 c2 31 ca 88 10 83 45 fc 01 83 45 f8 01 8b 45 f8 48 98 48 3b 45 18 72 9e } //1
		$a_01_1 = {ba e1 e8 c1 1a 48 89 c1 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}