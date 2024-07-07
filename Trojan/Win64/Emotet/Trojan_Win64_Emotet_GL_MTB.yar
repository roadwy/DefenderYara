
rule Trojan_Win64_Emotet_GL_MTB{
	meta:
		description = "Trojan:Win64/Emotet.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 b9 2f 00 00 00 f7 f9 48 63 ca 48 8b 05 90 01 04 0f b6 04 08 8b d7 33 d0 48 63 8c 24 90 01 04 48 8b 05 90 01 04 88 14 08 eb 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}