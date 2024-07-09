
rule TrojanSpy_Win32_Banker_gen_F{
	meta:
		description = "TrojanSpy:Win32/Banker.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b7 5c 78 fe 33 5d ?? 3b 5d ?? 7f 0b 81 c3 ff 00 00 00 } //1
		$a_00_1 = {70 00 65 00 64 00 72 00 6f 00 63 00 61 00 63 00 61 00 72 00 6e 00 65 00 69 00 72 00 6f 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //1 pedrocacarneiro@gmail.com
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}