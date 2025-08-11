
rule Trojan_Win64_CobaltStrike_WQ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.WQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b7 47 14 48 8d 14 9b 4c 01 e8 48 8d 34 d0 4c 89 f2 48 89 f1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}