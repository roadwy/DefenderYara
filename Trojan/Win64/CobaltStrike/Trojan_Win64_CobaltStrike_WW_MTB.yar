
rule Trojan_Win64_CobaltStrike_WW_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.WW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f3 0f 7f 4c 18 10 f3 0f 6f 44 18 20 66 0f 6f ca 66 0f fc c8 f3 0f 7f 4c 18 20 f3 0f 6f 44 18 30 66 0f 6f ca 66 0f fc c8 f3 0f 7f 4c 18 30 48 83 c0 40 48 3d 00 04 04 00 7c a6 } //1
		$a_01_1 = {52 65 6c 65 61 73 65 5c 6d 6f 76 65 6e 70 65 61 6b 2e 70 64 62 } //1 Release\movenpeak.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}