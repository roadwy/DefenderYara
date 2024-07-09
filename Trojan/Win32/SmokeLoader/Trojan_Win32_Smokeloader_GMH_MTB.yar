
rule Trojan_Win32_Smokeloader_GMH_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f3 33 f0 2b fe 8b d7 c1 e2 ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 5c 24 ?? 8b 0d ?? ?? ?? ?? 03 df 81 f9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}