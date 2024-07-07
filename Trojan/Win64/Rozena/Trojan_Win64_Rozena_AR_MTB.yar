
rule Trojan_Win64_Rozena_AR_MTB{
	meta:
		description = "Trojan:Win64/Rozena.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f3 0f 6f 41 e0 83 c0 40 48 8d 49 40 66 0f f8 c2 f3 0f 7f 41 a0 f3 0f 6f 41 b0 66 0f f8 c2 f3 0f 7f 41 b0 f3 0f 6f 49 c0 66 0f f8 ca f3 0f 7f 49 c0 f3 0f 6f 41 d0 66 0f f8 c2 f3 0f 7f 41 d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}