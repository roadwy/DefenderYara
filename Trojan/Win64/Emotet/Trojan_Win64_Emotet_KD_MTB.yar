
rule Trojan_Win64_Emotet_KD_MTB{
	meta:
		description = "Trojan:Win64/Emotet.KD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 84 24 f0 81 00 00 0f b6 bc 04 40 76 00 00 8b 84 24 f0 81 00 00 99 b9 ?? ?? ?? ?? f7 f9 48 63 ca 48 8b 05 ?? ?? ?? ?? 0f b6 04 08 8b d7 33 d0 48 63 8c 24 ?? ?? ?? ?? 48 8b 84 24 ?? ?? ?? ?? 88 14 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}