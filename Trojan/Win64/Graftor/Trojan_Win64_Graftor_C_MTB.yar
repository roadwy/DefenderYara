
rule Trojan_Win64_Graftor_C_MTB{
	meta:
		description = "Trojan:Win64/Graftor.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 d1 ff c1 41 51 42 31 8c 1c ?? ?? ?? ?? 44 23 d2 41 59 40 0a d7 40 0a f7 48 03 c6 48 63 c9 40 c0 cf } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}