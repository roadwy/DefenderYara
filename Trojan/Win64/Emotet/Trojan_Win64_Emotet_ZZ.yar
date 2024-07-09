
rule Trojan_Win64_Emotet_ZZ{
	meta:
		description = "Trojan:Win64/Emotet.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {8b cb 41 8b d0 d3 e2 41 8b cb d3 e0 03 d0 41 0f be ?? 03 d0 41 2b d0 49 ff ?? (44 8b c2 45 8a|45 8a ?? 44 8b c2 )} //10
		$a_03_2 = {41 8b c0 45 84 ?? 75 d8 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10) >=21
 
}