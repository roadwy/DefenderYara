
rule Trojan_Win64_CobaltStrike_CBZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 c3 0f b6 c8 40 02 f1 40 02 f5 40 0f b6 ce 41 0f b6 44 8f 08 41 30 45 00 41 8b 44 8f 08 41 31 44 97 08 43 8b 44 a7 ?? 8d 0c 07 43 31 4c 87 08 48 83 7c 24 50 10 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}