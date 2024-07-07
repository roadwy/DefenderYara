
rule TrojanDropper_WinNT_Scrivb_A{
	meta:
		description = "TrojanDropper:WinNT/Scrivb.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 90 02 0f 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 90 00 } //1
		$a_02_1 = {6f 6e 20 65 72 72 6f 72 20 72 65 73 75 6d 65 20 6e 65 78 74 3a 90 02 06 3d 20 41 72 72 61 79 28 90 00 } //1
		$a_02_2 = {5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 90 02 0e 2e 00 76 00 62 00 73 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}