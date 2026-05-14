
rule Trojan_Win64_CobaltStrike_BCMD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BCMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 7c 24 ?? 48 63 f6 89 f3 49 0f af db 48 c1 eb ?? c1 e3 ?? 8d 1c 9b 41 89 f6 41 29 de 42 0f b6 1c 32 32 1c 37 88 1c 31 ff c6 83 fe 0d 4c 89 cf 49 0f 44 fa eb } //2
		$a_01_1 = {45 30 04 0f 45 02 04 0f e2 f6 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}