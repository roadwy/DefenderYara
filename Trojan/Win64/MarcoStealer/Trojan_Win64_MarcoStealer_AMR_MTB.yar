
rule Trojan_Win64_MarcoStealer_AMR_MTB{
	meta:
		description = "Trojan:Win64/MarcoStealer.AMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {32 56 f1 88 56 01 32 5e f2 88 5e 02 44 32 4e f3 44 88 4e 03 32 46 f4 88 46 04 32 56 f5 88 56 05 32 5e f6 88 5e 06 32 d9 44 32 4e f7 44 88 4e 07 44 32 cf 32 46 f8 88 46 08 41 32 c3 32 56 f9 88 56 09 41 32 d2 88 56 0d 88 5e 0a 44 88 4e 0b 88 46 0c } //2
		$a_01_1 = {54 43 58 4d 4f 55 43 59 52 47 41 54 4e 4f 52 4f 4f } //1 TCXMOUCYRGATNOROO
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}