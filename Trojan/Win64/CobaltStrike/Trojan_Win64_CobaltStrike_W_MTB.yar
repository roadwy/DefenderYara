
rule Trojan_Win64_CobaltStrike_W_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.W!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 53 80 f4 ?? 48 89 ca 89 c8 4c 8b 4d ?? 89 c0 4c 89 ca 89 d1 09 c0 48 8b 95 } //2
		$a_03_1 = {89 c6 4d 29 d0 48 33 45 ?? 88 cc 48 39 c9 } //4
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*4) >=6
 
}