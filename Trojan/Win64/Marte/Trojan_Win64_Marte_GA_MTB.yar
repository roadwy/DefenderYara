
rule Trojan_Win64_Marte_GA_MTB{
	meta:
		description = "Trojan:Win64/Marte.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {49 63 c9 4d 8d 52 ?? 49 3b c8 49 8b d6 48 0f 45 d0 0f b6 44 14 ?? 41 30 42 ff 41 8b c6 49 3b c8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}