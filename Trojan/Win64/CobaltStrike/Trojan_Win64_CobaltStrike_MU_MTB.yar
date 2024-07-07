
rule Trojan_Win64_CobaltStrike_MU_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 44 24 61 49 8b d7 8a 44 24 61 2a c3 34 54 88 44 24 62 8a 44 24 62 2a c3 32 c1 88 44 24 63 8a 44 24 63 2a c3 34 72 88 44 24 64 } //5
		$a_01_1 = {5c 53 68 65 6c 6c 63 6f 64 65 5c 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 2e 70 64 62 } //5 \Shellcode\ReflectiveLoader.pdb
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}