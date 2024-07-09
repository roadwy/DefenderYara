
rule Trojan_Win64_Iceid_PD_MTB{
	meta:
		description = "Trojan:Win64/Iceid.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 f7 f1 48 8b c2 48 8b 4c 24 ?? 66 3b f6 74 45 } //1
		$a_03_1 = {33 d2 48 8b c1 b9 08 00 00 00 3a db 74 ?? 8b c1 48 63 4c 24 ?? 48 8b 54 24 } //1
		$a_03_2 = {0f b6 44 01 ?? 8b 4c 24 ?? 33 c8 66 3b ff 74 ca } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}