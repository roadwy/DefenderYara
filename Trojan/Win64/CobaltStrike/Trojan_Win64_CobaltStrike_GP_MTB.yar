
rule Trojan_Win64_CobaltStrike_GP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 ff c0 48 89 45 28 8b 85 48 01 00 00 48 39 45 28 73 32 48 8b 45 28 48 8b 8d 40 01 00 00 48 03 c8 48 8b c1 0f be 00 33 05 8d 15 01 00 33 05 8b 15 01 00 48 8b 4d 28 48 8b 55 08 48 03 d1 48 8b ca 88 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}