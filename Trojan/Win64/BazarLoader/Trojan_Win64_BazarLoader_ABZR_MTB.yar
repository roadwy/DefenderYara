
rule Trojan_Win64_BazarLoader_ABZR_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.ABZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 83 c0 01 99 c1 ea 18 01 d0 0f b6 c0 29 d0 89 45 fc 8b 45 fc 48 63 d0 48 8b 45 20 48 01 d0 0f b6 00 0f b6 d0 8b 45 f8 01 d0 99 c1 ea 18 01 d0 0f b6 c0 29 d0 89 45 f8 8b 45 fc 48 63 d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}