
rule Trojan_Win64_ReedBed_B_ldr{
	meta:
		description = "Trojan:Win64/ReedBed.B!ldr,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8b 71 30 41 bf 01 00 00 ?? 4c 23 f0 48 03 d9 45 2b e7 44 8b 5b 20 41 f7 d4 4c 8d 43 18 4d 0b de 48 8b f2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}