
rule Trojan_Win64_Disco_SBB_MTB{
	meta:
		description = "Trojan:Win64/Disco.SBB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 20 02 00 00 00 ff 15 df 1b 02 00 48 8b 3d f0 1c 02 00 49 89 c4 8a 03 48 ff c3 4d 89 e9 41 b8 01 00 00 00 48 c7 44 24 20 00 00 00 00 48 89 ea 4c 89 e1 83 f0 aa 88 44 24 4b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}