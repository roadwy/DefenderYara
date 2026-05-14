
rule Trojan_Win64_DarkSideRat_ADS_MTB{
	meta:
		description = "Trojan:Win64/DarkSideRat.ADS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 bf 3c b6 22 f7 e9 c1 fa 03 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 3b 0f b6 c1 2a c2 04 3a 32 07 34 37 88 07 ff c1 48 8d 7f 01 83 f9 32 } //2
		$a_03_1 = {48 8b f0 8b 05 ?? 3e 00 00 89 44 24 30 0f b6 05 ?? 3e 00 00 c6 44 24 30 2e 80 74 24 31 0c 80 74 24 32 0b 80 74 24 33 0a 34 09 88 44 24 34 48 8d 44 24 30 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}