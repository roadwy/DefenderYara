
rule TrojanDropper_Win32_VB_YCE{
	meta:
		description = "TrojanDropper:Win32/VB.YCE,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {5c 00 4d 00 65 00 6c 00 74 00 2e 00 62 00 61 00 74 00 [0-12] 54 00 65 00 6d 00 70 00 [0-12] 5c 00 63 00 6f 00 70 00 69 00 65 00 64 00 66 00 69 00 6c 00 65 00 2e 00 65 00 78 00 65 00 [0-12] 4d 00 65 00 6c 00 74 00 2e 00 62 00 61 00 74 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}