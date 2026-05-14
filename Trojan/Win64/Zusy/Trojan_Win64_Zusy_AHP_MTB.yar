
rule Trojan_Win64_Zusy_AHP_MTB{
	meta:
		description = "Trojan:Win64/Zusy.AHP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 0f b6 14 10 47 32 54 0b 01 4d 8d 41 02 41 c0 c2 ?? 47 88 54 0b 01 83 c0 ?? 83 e0 ?? 4d 89 c1 4c 39 c1 75 } //30
		$a_03_1 = {49 09 db 49 c1 e5 ?? 4d 09 dd 41 c1 e6 ?? 4d 09 ee 48 8b 55 e8 c1 e2 ?? 4c 09 f2 41 c1 e2 ?? 49 09 d2 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}