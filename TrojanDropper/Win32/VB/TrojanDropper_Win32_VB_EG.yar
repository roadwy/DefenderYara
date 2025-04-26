
rule TrojanDropper_Win32_VB_EG{
	meta:
		description = "TrojanDropper:Win32/VB.EG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {6e 00 74 00 64 00 6c 00 6c 00 00 00 28 00 00 00 4e 00 74 00 55 00 6e 00 6d 00 61 00 70 00 56 00 69 00 65 00 77 00 4f 00 66 00 53 00 65 00 63 00 74 00 69 00 6f 00 6e 00 00 00 } //1
		$a_01_1 = {f3 00 01 c1 e7 04 58 ff 9d fb 12 fc 0d 6c 50 ff 6c 40 ff fc a0 00 0a 04 50 ff 66 ec fe db 01 00 26 f5 00 00 00 00 f5 40 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}