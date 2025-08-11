
rule Trojan_Win64_CobaltStrike_GZK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 03 d2 48 03 fa 45 33 c9 45 8b 02 41 8b c9 4c 03 c2 41 8a 00 49 ff c0 c1 c9 0d 0f be c0 03 c8 41 8a 00 84 c0 } //5
		$a_01_1 = {50 33 c9 41 b8 00 30 00 00 44 8d 49 40 41 ff } //5
		$a_01_2 = {3f 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 40 40 59 41 5f 4b 50 45 41 58 40 5a } //1 ?ReflectiveLoader@@YA_KPEAX@Z
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}