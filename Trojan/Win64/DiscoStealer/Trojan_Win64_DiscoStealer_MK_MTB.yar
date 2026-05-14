
rule Trojan_Win64_DiscoStealer_MK_MTB{
	meta:
		description = "Trojan:Win64/DiscoStealer.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 48 8d 49 01 41 8b c1 41 ff c1 41 f7 f6 0f b6 04 3a 32 44 0b ff 88 41 ff 44 3b ce } //35
	condition:
		((#a_01_0  & 1)*35) >=35
 
}