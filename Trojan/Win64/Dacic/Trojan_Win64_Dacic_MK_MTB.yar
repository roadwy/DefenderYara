
rule Trojan_Win64_Dacic_MK_MTB{
	meta:
		description = "Trojan:Win64/Dacic.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_03_0 = {4d 09 c3 4d 09 de 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? 4c 31 f1 49 c1 e7 ?? 48 c1 e3 ?? 4c 09 fb 49 c1 e4 ?? 49 09 dc 49 c1 e1 ?? 4d 09 e1 c1 e7 18 } //20
		$a_03_1 = {48 09 ca 49 c1 e2 ?? 49 09 d2 48 c1 e5 ?? 4c 09 d5 41 c1 e3 ?? 49 09 eb 44 0f b6 94 24 ?? ?? ?? ?? 41 c1 e0 ?? 4d 09 d8 0f b6 94 24 } //15
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*15) >=35
 
}