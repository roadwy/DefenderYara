
rule Trojan_Win64_MildTailor_A_dha{
	meta:
		description = "Trojan:Win64/MildTailor.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b7 c7 41 8b 54 85 00 0f b7 04 41 49 03 d6 45 8b 1c 84 4d 03 de 80 7a 01 77 } //1
		$a_03_1 = {33 d2 41 f7 f3 32 d3 41 3a d0 74 ?? 44 32 c2 eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}