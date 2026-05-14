
rule Trojan_Win64_ACRStealer_AHA_MTB{
	meta:
		description = "Trojan:Win64/ACRStealer.AHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 89 ca 41 09 f1 44 21 d6 41 29 f1 45 31 c8 44 88 04 38 48 8d 57 ff } //30
		$a_03_1 = {0f b6 30 0f b6 7c 24 ?? 31 f7 40 88 38 31 d2 eb } //20
	condition:
		((#a_01_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}