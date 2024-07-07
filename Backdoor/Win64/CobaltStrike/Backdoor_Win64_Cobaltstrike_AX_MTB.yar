
rule Backdoor_Win64_Cobaltstrike_AX_MTB{
	meta:
		description = "Backdoor:Win64/Cobaltstrike.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 41 01 45 0f b6 01 49 63 ca 41 ff c2 4c 0f af c3 4c 03 c0 49 8b c7 48 ff cb 48 f7 e1 4d 0f af c3 48 8b c1 48 2b c2 49 ff c3 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 90 01 01 48 2b c8 0f b6 44 0d 90 01 01 43 30 04 20 41 81 fa 90 01 04 72 90 00 } //1
		$a_03_1 = {43 0f b6 04 0b 49 63 ca 41 ff c2 4d 8d 5b 01 4c 69 c0 90 01 04 41 0f b6 01 49 ff c8 4c 0f af c0 48 8b c6 48 f7 e1 90 02 30 48 2b c8 0f b6 44 90 01 02 43 30 44 18 ff 41 81 fa 90 01 04 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}