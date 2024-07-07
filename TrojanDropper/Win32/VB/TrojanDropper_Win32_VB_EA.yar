
rule TrojanDropper_Win32_VB_EA{
	meta:
		description = "TrojanDropper:Win32/VB.EA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4a fe 64 ec fe 72 02 00 14 6c 4c ff f5 01 00 00 00 aa f5 00 01 00 00 c2 71 4c ff 00 17 6c 48 ff 6c 4c ff 04 58 ff 9d e7 aa f5 00 01 00 00 c2 71 } //1
		$a_01_1 = {f5 00 00 00 00 59 80 fc 6c 90 fe f5 00 00 00 00 80 10 00 2e e8 fc 40 6c 70 fe 6c b8 fd 0a 09 00 14 00 3c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}