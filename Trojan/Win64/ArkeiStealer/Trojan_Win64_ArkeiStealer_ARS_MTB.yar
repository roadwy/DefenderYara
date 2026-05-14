
rule Trojan_Win64_ArkeiStealer_ARS_MTB{
	meta:
		description = "Trojan:Win64/ArkeiStealer.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 31 c0 47 8b 4c 3e ?? 45 31 e9 43 8b 04 3e 44 31 e0 41 0f b7 c9 41 c1 e9 ?? 89 c2 c1 ea } //5
		$a_01_1 = {8d 48 ff 83 e1 1e 0f b6 8c 0d 40 03 00 00 30 4c 06 ff 89 c1 83 e1 1f 0f b6 8c 0d 40 03 00 00 30 0c 06 48 83 c0 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}