
rule Trojan_Win64_CobaltStrike_FTA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 f6 89 f3 49 0f af db 48 c1 eb 24 8d 2c 5b c1 e5 03 29 eb 01 f3 0f b6 1c 1a 32 1c 37 88 1c 31 ff c6 83 fe 0d 4c 89 d7 49 0f 44 f9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}