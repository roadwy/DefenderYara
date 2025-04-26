
rule Worm_Win32_Nayrabot_gen_A{
	meta:
		description = "Worm:Win32/Nayrabot.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 6c 6f 6f 64 69 6e 67 3a 20 22 25 73 3a 25 64 22 2c 20 44 65 6c 61 79 3a } //1 Flooding: "%s:%d", Delay:
		$a_01_1 = {49 6e 66 65 63 74 65 64 20 52 65 6d 6f 76 61 62 6c 65 20 44 65 76 69 63 65 3a 20 22 25 73 5c 22 } //1 Infected Removable Device: "%s\"
		$a_01_2 = {41 72 79 61 4e 7b 25 73 } //1 AryaN{%s
		$a_01_3 = {52 65 70 6c 61 63 65 64 20 41 72 79 61 4e 20 46 69 6c 65 20 57 69 74 68 20 4e 65 77 6c 79 20 44 6f 77 6e 6c 6f 61 64 20 46 69 6c 65 } //1 Replaced AryaN File With Newly Download File
		$a_03_4 = {6a 5b 59 50 53 53 68 1a 80 00 00 f3 a5 53 ff 15 ?? ?? ?? ?? 85 c0 7d } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*2) >=4
 
}