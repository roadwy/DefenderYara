
rule Trojan_Win64_Cobaltstrike_BPD_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.BPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8d 44 24 40 48 83 7c 24 58 0f 4c 0f 47 44 24 40 48 8d 8d b0 02 00 00 33 d2 49 8b c1 49 f7 f4 48 03 d1 48 8d 8d d0 02 00 00 48 83 bd e8 02 00 00 0f 48 0f 47 8d d0 02 00 00 43 0f b6 04 08 32 02 42 88 04 09 49 ff c1 4c 3b 4c 24 50 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}