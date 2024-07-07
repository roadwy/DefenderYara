
rule Trojan_Win32_Vundo_gen_AB{
	meta:
		description = "Trojan:Win32/Vundo.gen!AB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 e1 00 75 90 01 01 eb 90 14 74 90 14 70 90 01 01 eb 90 00 } //3
		$a_03_1 = {ed ea 2d 00 10 00 00 8b 08 81 e1 ff ff 00 00 31 90 01 05 81 f9 4d 5a 00 00 0f 85 90 00 } //3
		$a_80_2 = {4d 69 63 72 6f 73 6f 66 74 20 43 6f 72 70 6f 72 61 74 69 6f 6e } //Microsoft Corporation  1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_80_2  & 1)*1) >=6
 
}