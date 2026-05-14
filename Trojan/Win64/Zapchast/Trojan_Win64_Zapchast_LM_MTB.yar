
rule Trojan_Win64_Zapchast_LM_MTB{
	meta:
		description = "Trojan:Win64/Zapchast.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 0e 48 ff c7 32 44 2f ff 88 44 0f ff } //20
		$a_01_1 = {8b cf c1 e9 05 03 4d 0c 8b c7 c1 e0 04 03 45 08 33 c8 41 8d 04 3c 33 c8 2b f1 8b 84 24 88 00 00 00 44 89 b4 24 88 00 00 00 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}