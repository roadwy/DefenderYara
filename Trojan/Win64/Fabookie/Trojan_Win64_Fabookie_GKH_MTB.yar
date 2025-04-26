
rule Trojan_Win64_Fabookie_GKH_MTB{
	meta:
		description = "Trojan:Win64/Fabookie.GKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b ec 48 83 ec ?? c7 45 ?? 48 8b c4 48 c7 45 ?? 89 58 08 4c c7 45 ?? 89 40 18 48 c7 45 ?? 89 50 10 55 c7 45 ?? 56 57 48 83 66 c7 45 ?? ec 30 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}