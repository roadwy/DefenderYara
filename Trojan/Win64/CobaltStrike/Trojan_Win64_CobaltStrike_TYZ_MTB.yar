
rule Trojan_Win64_CobaltStrike_TYZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.TYZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {b8 09 cb 3d 8d 41 f7 e0 c1 ea 05 0f be c2 6b c8 3a 41 8a c0 41 ff c0 2a c1 04 36 41 30 01 49 ff c1 41 83 f8 18 7c d9 } //2
		$a_01_1 = {8b c6 41 f7 e0 c1 ea 05 0f be c2 6b c8 3a 41 8a c0 2a c1 04 36 41 30 01 44 03 c3 4c 03 cb 41 83 f8 15 7c dc } //2
		$a_01_2 = {4a 4d 4f 5a 50 6d 4c 50 34 24 } //1 JMOZPmLP4$
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}