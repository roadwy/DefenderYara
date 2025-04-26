
rule Trojan_Win64_ReedBed_AL_MTB{
	meta:
		description = "Trojan:Win64/ReedBed.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b d1 8b ca 48 63 c9 48 0f af c1 0f b6 44 04 ?? 8b 8c 24 ?? 00 00 00 33 c8 8b c1 48 63 4c 24 ?? 48 8b 94 24 ?? 00 00 00 88 04 0a e9 } //3
		$a_03_1 = {33 d2 48 8b c1 b9 ?? 00 00 00 48 f7 f1 48 8b c2 b9 01 00 00 00 48 6b c9 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}