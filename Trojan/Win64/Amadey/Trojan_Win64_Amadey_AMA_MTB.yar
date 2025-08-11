
rule Trojan_Win64_Amadey_AMA_MTB{
	meta:
		description = "Trojan:Win64/Amadey.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 98 48 01 d0 0f b6 00 32 45 20 89 c1 48 8b 55 28 8b 45 fc 48 98 48 01 d0 88 08 8b 4d fc } //2
		$a_03_1 = {48 98 48 01 d0 88 08 8b 4d fc 48 63 c1 48 69 c0 ?? ?? ?? ?? 48 c1 e8 20 48 89 c2 89 c8 c1 f8 1f 29 c2 89 d0 01 c0 01 d0 29 c1 89 ca 85 d2 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}