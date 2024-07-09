
rule TrojanDropper_Win32_Cybergate_MR{
	meta:
		description = "TrojanDropper:Win32/Cybergate.MR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {63 6d 64 20 2f 63 20 3c 6e 75 6c 20 73 65 74 20 2f 70 20 3d 22 4d 22 20 3e 20 6c 73 61 73 73 2e 63 6f 6d 20 26 20 74 79 70 65 [0-08] 2e 63 6f 6d 20 3e 3e 20 6c 73 61 73 73 2e 63 6f 6d 20 26 20 64 65 6c [0-08] 2e 63 6f 6d 20 26 20 63 65 72 74 75 74 69 6c 20 2d 64 65 63 6f 64 65 [0-08] 2e 63 6f 6d 20 52 20 26 20 6c 73 61 73 73 2e 63 6f 6d 20 52 20 26 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}