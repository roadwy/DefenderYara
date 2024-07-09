
rule Trojan_BAT_SpyNoon_SHEBJK_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SHEBJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 16 03 28 ?? ?? ?? 0a 0a 07 20 f5 2f d4 71 5a 20 73 d1 7c 9d 61 2b cd 06 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}