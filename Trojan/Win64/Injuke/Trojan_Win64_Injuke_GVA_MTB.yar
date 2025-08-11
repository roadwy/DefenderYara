
rule Trojan_Win64_Injuke_GVA_MTB{
	meta:
		description = "Trojan:Win64/Injuke.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 89 c2 46 8a 1c 00 89 c1 80 e1 03 41 d2 cb 41 83 e2 0f 43 8a 0c 0a 80 e1 0f 44 30 d9 88 0c 32 48 ff c6 48 ff c0 48 3d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}