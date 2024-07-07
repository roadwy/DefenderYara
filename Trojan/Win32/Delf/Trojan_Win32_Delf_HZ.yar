
rule Trojan_Win32_Delf_HZ{
	meta:
		description = "Trojan:Win32/Delf.HZ,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {76 6d 77 61 72 65 2e 65 78 65 7c } //1 vmware.exe|
		$a_01_1 = {2a 67 6f 6f 67 6c 65 2a 2e 74 78 74 } //1 *google*.txt
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 00 00 00 ff ff ff ff 17 00 00 00 44 69 73 61 62 6c 65 53 63 72 69 70 74 44 65 62 75 67 67 65 72 49 45 } //1
		$a_01_3 = {67 72 6f 75 70 73 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 67 72 70 68 70 3f 68 6c 3d 7a 68 2d 43 4e 26 6e 65 64 3d 63 6e 26 74 61 62 3d 6e 67 } //1 groups.google.com/grphp?hl=zh-CN&ned=cn&tab=ng
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}