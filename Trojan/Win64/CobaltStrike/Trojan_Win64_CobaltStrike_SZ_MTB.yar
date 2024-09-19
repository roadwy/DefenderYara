
rule Trojan_Win64_CobaltStrike_SZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0a 83 f1 ?? 48 83 c2 01 88 4a ff 4c 39 c2 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}