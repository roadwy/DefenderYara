
rule Trojan_Win64_XWorm_GVA_MTB{
	meta:
		description = "Trojan:Win64/XWorm.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 55 10 48 8b 45 f0 48 01 d0 0f b6 00 0f be d0 8b 45 fc 01 c2 8b 45 fc c1 e0 0a 01 c2 8b 45 fc c1 e8 06 31 d0 89 45 fc 48 83 45 f0 01 48 8b 45 10 48 89 c1 ?? ?? ?? ?? ?? 48 39 45 f0 72 c0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}