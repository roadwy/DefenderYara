
rule Trojan_Win64_Andariel_KAA_MTB{
	meta:
		description = "Trojan:Win64/Andariel.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 98 40 30 34 08 0f b6 53 0e 41 8d 40 0e 48 98 30 14 08 0f b6 5b 0f 41 8d 40 0f 48 98 30 1c 08 48 8b 4d 90 48 89 8d 60 ff ff ff 48 8b 55 98 48 89 95 68 ff ff ff 41 83 c6 10 41 ff c5 49 63 f5 49 3b f7 0f 82 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}