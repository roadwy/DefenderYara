
rule Trojan_Win64_DanaBot_SA_MTB{
	meta:
		description = "Trojan:Win64/DanaBot.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 0f b6 00 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 0f af 45 ?? 0f af 45 ?? 8b 4d ?? 03 c8 33 4d ?? 89 4d ?? 83 45 ?? ?? 83 eb ?? 85 db 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}