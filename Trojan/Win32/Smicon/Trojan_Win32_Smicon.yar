
rule Trojan_Win32_Smicon{
	meta:
		description = "Trojan:Win32/Smicon,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 69 63 6f 6e 20 67 75 69 64 65 00 } //1
		$a_01_1 = {2f 73 6d 61 72 74 69 63 6f 6e 2f 69 6e 73 74 61 6c 6c 2e 70 68 70 3f 6d 61 63 3d 25 73 26 70 61 72 74 6e 65 72 3d 25 73 } //1 /smarticon/install.php?mac=%s&partner=%s
		$a_01_2 = {2f 63 6f 75 6e 74 2f 69 6e 73 74 61 6c 6c 2e 70 68 70 3f 6d 61 63 3d 25 73 26 70 61 72 74 6e 65 72 3d 25 73 } //1 /count/install.php?mac=%s&partner=%s
		$a_01_3 = {2f 6e 65 77 75 70 64 61 74 65 72 00 } //1 港睥灵慤整r
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}