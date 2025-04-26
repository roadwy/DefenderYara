
rule Trojan_Win32_Emotet_BR{
	meta:
		description = "Trojan:Win32/Emotet.BR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {72 2e 34 59 4d 34 71 68 43 7a 35 44 61 76 6e 43 6f 50 68 6a 6a 78 2e 70 64 62 } //3 r.4YM4qhCz5DavnCoPhjjx.pdb
		$a_00_1 = {6b 4f 40 66 62 4c 4c 45 46 6d 6b 32 49 5f 4d 2e 70 64 62 } //3 kO@fbLLEFmk2I_M.pdb
		$a_01_2 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 6d 00 69 00 63 00 72 00 6f 00 2e 00 65 00 78 00 65 } //1
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*3+(#a_01_2  & 1)*1) >=4
 
}