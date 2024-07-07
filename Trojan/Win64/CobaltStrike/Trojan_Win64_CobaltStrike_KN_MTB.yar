
rule Trojan_Win64_CobaltStrike_KN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.KN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 cb 41 0f b6 44 8e 90 01 01 41 30 47 90 01 01 41 8b 44 8e 90 01 01 41 31 44 96 90 01 01 41 8b 44 ae 90 01 01 41 8d 0c 00 43 31 4c 96 90 01 01 40 fe c5 40 0f b6 ed 41 8b 7c ae 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}