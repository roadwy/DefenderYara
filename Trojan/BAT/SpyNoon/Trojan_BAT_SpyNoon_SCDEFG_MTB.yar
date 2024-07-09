
rule Trojan_BAT_SpyNoon_SCDEFG_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SCDEFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 ac 05 d7 a6 20 7b 82 37 c7 61 25 0b 19 5e 45 03 00 00 00 e0 ff ff ff 18 00 00 00 02 00 00 00 2b 16 03 28 ?? ?? ?? 0a 0a 07 20 31 d4 3d 39 5a 20 6e e2 ab 4d 61 2b cd 06 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}