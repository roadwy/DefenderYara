
rule Worm_Win32_Koobface_gen_A{
	meta:
		description = "Worm:Win32/Koobface.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {53 54 41 52 54 4f 4e 43 45 00 [0-10] 25 73 5c 74 74 5f 25 64 2e 65 78 65 00 } //2
		$a_03_1 = {4c 49 4e 4b 54 45 58 54 5f 4d 00 [0-03] 54 45 58 54 5f 4d 00 } //1
		$a_01_2 = {4c 49 4e 4b 5f 4d 00 00 54 45 58 54 5f 4d 00 } //1
		$a_03_3 = {d4 dc ff ff 68 ?? ?? 40 00 50 ff 15 ?? ?? 40 00 83 c4 1c } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}