
rule Trojan_Win64_CobaltStrike_EMP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.EMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 c0 89 44 24 2c 8b 54 24 2c 89 d0 c1 e8 1f 01 d0 d1 f8 89 44 24 2c 8b 44 24 2c 35 aa aa 00 00 89 44 24 2c 8b 44 24 2c 0f b7 c0 89 44 24 2c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}