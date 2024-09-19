
rule Trojan_Win64_DarkGate_MZY_MTB{
	meta:
		description = "Trojan:Win64/DarkGate.MZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 03 cd 49 8b c8 49 f7 e0 48 2b ca 48 d1 e9 48 03 ca 48 c1 e9 04 48 6b c1 19 4c 2b c0 42 8a 44 04 ?? 43 32 04 13 41 88 02 4d 03 d5 44 3b ce 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}