
rule Trojan_Win64_Cobaltstrike_FD_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.FD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 0f b6 c2 45 32 c9 45 03 c3 41 c1 e0 02 41 0f b6 c1 41 fe c1 41 03 c0 8a 0c 38 30 0a 48 ff c2 41 80 f9 04 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}