
rule Trojan_Win64_Midie_SXI_MTB{
	meta:
		description = "Trojan:Win64/Midie.SXI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 01 ?? ?? ?? ?? 34 5f 88 44 0d ?? 48 ff c1 48 8d 05 ?? ?? ?? ?? 48 83 f9 0d 75 e2 } //30
		$a_01_1 = {80 f1 5f 4c 39 74 24 68 48 0f 47 44 24 50 88 48 08 48 8d 44 24 50 0f b6 4d 99 80 f1 5f 4c 39 74 24 68 48 0f 47 44 24 50 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}