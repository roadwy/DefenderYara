
rule TrojanProxy_Win32_Tinxy_H{
	meta:
		description = "TrojanProxy:Win32/Tinxy.H,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 72 6f 63 65 73 73 2d 63 6c 69 63 6b 73 3a 00 } //1
		$a_01_1 = {70 72 6f 63 65 73 73 2d 72 65 66 65 72 65 72 3a 00 } //1
		$a_01_2 = {49 47 59 4d 41 53 00 } //1
		$a_01_3 = {c6 47 ff 25 c6 07 32 83 c4 10 c6 47 01 30 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=4
 
}