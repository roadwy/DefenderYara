
rule PWS_Win32_Delfsnif_gen_G{
	meta:
		description = "PWS:Win32/Delfsnif.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 6e 64 3b 6d 65 6e 61 6d 65 65 78 65 3a 00 00 ff ff ff ff 0e 00 00 00 65 6e 64 3b 6d 65 6e 61 } //1
		$a_01_1 = {3b 6d 65 6e 61 6d 65 64 6c 6c 3a 00 00 ff ff ff ff 0b 00 00 00 65 6e 64 3b 73 78 70 6f 72 74 3a } //1
		$a_03_2 = {63 6d 64 2e 65 78 65 00 55 8b ec 33 c0 55 68 ?? ?? 41 00 64 ff 30 64 89 20 b8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}