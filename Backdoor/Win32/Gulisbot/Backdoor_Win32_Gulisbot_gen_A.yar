
rule Backdoor_Win32_Gulisbot_gen_A{
	meta:
		description = "Backdoor:Win32/Gulisbot.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0e 00 04 00 00 "
		
	strings :
		$a_03_0 = {76 15 8a 83 ?? ?? ?? ?? 55 30 04 3e 43 e8 ?? ?? 00 00 3b d8 59 72 eb 8a 04 3e 57 f6 d0 88 04 3e 46 e8 ?? ?? 00 00 3b f0 59 72 ca } //2
		$a_03_1 = {99 b9 bf 63 00 00 8b 5d 08 f7 f9 6a 03 89 5d d8 81 ea c0 63 00 00 90 09 07 00 75 4c e8 ?? ?? 00 } //2
		$a_03_2 = {75 51 6a 7f ff 74 be 04 68 ?? ?? ?? ?? e8 ?? ?? 00 00 ff 74 be 08 e8 ?? ?? 00 00 6a 1f a3 ?? ?? ?? ?? ff 74 be 0c } //2
		$a_01_3 = {61 73 70 65 72 67 69 6c 6c 75 73 } //10 aspergillus
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*10) >=14
 
}