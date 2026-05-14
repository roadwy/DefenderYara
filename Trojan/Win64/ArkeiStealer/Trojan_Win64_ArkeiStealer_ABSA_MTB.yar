
rule Trojan_Win64_ArkeiStealer_ABSA_MTB{
	meta:
		description = "Trojan:Win64/ArkeiStealer.ABSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 01 fb 45 31 dd 41 c1 c5 ?? 45 01 e8 44 31 c7 c1 c7 0c 41 01 fb 45 31 dd 41 c1 c5 ?? 45 01 e8 44 31 c7 c1 c7 07 ff 4c 24 34 } //5
		$a_01_1 = {8d 48 ff 83 e1 1e 0f b6 4c 0d d0 30 4c 03 ff 89 c1 83 e1 1f 0f b6 4c 0d d0 30 0c 03 48 83 c0 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}