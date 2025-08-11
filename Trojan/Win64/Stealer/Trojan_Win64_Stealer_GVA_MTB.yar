
rule Trojan_Win64_Stealer_GVA_MTB{
	meta:
		description = "Trojan:Win64/Stealer.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {41 0f b6 d1 40 32 d6 0f b6 c8 d2 fa 49 c1 e8 ?? 42 8b 4c 84 ?? f6 c2 01 8b d0 } //2
		$a_01_1 = {8b 4c 24 58 43 88 0c 2f 41 ff c7 45 3b fc } //1
	condition:
		((#a_02_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}