
rule Backdoor_Win32_Wingbird_gen_A{
	meta:
		description = "Backdoor:Win32/Wingbird.gen.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {33 c5 89 45 fc 8b 4d 08 53 56 57 33 c0 0f 84 } //1
		$a_03_1 = {8d 64 24 0c 33 c9 81 e9 90 01 04 51 81 f1 90 01 04 51 81 c1 90 01 04 51 81 e9 90 01 04 51 81 f1 90 01 04 51 54 ff b5 90 01 02 ff ff ff 15 90 00 } //3
		$a_03_2 = {33 c9 81 e9 90 01 04 51 81 f1 90 01 04 51 54 ff b5 90 01 02 ff ff ff 15 90 00 } //1
		$a_03_3 = {03 49 3c 0f 90 01 03 00 00 90 13 0f b7 51 14 90 13 83 c2 14 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*3+(#a_03_2  & 1)*1+(#a_03_3  & 1)*2) >=5
 
}