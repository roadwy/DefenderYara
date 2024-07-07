
rule Trojan_Win64_TrickBotCrypt_ER_MTB{
	meta:
		description = "Trojan:Win64/TrickBotCrypt.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 0f b6 04 21 03 c8 b8 ab 00 a0 aa f7 e1 c1 ea 0d 69 d2 03 30 00 00 2b ca 48 63 c1 48 2b c7 48 03 44 24 20 48 03 c6 42 0f b6 04 20 43 30 04 3a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}