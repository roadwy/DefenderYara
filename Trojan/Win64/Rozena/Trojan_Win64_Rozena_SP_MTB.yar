
rule Trojan_Win64_Rozena_SP_MTB{
	meta:
		description = "Trojan:Win64/Rozena.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f3 0f 6f 41 f0 48 8d 49 40 0f 57 c9 66 0f f8 c8 f3 0f 7f 49 b0 0f 57 c9 f3 0f 6f 41 c0 66 0f f8 c8 f3 0f 7f 49 c0 0f 57 c9 f3 0f 6f 41 d0 66 0f f8 c8 f3 0f 7f 49 d0 0f 57 c9 f3 0f 6f 41 e0 66 0f f8 c8 f3 0f 7f 49 e0 48 83 ea 01 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}