
rule Trojan_Win64_Cobaltstrike_RDE_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c9 4d 8d 40 01 49 83 f9 60 49 0f 45 c9 0f b6 44 0c 40 43 32 44 18 ff 42 88 84 04 af 00 00 00 33 c0 49 83 f9 60 4c 8d 49 01 0f 45 c2 41 ff c2 8d 50 01 41 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}