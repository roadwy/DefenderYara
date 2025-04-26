
rule Trojan_Win64_Cobaltstrike_PNK_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.PNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f3 0f 6f 40 e0 48 8d 40 40 66 0f 6f ca 0f 57 c8 f3 0f 7f 48 a0 66 0f 6f ca f3 0f 6f 40 b0 0f 57 c2 f3 0f 7f 40 b0 f3 0f 6f 40 c0 0f 57 c8 f3 0f 7f 48 c0 66 0f 6f ca f3 0f 6f 40 d0 0f 57 c8 f3 0f 7f 48 d0 48 83 e9 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}