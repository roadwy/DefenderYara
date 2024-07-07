
rule Trojan_Win32_Zloader_BM_MSR{
	meta:
		description = "Trojan:Win32/Zloader.BM!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 69 72 63 6c 65 6f 70 70 6f 73 69 74 65 } //1 Circleopposite
		$a_01_1 = {43 72 65 61 74 65 46 69 6c 65 32 } //1 CreateFile2
		$a_01_2 = {63 3a 5c 46 6c 6f 77 65 72 53 70 72 69 6e 67 5c 4a 75 6d 70 45 76 65 6e 5c 54 68 72 6f 75 67 68 6f 62 73 65 72 76 65 5c 77 69 6c 6c 45 61 73 65 5c 45 79 65 2e 70 64 62 } //1 c:\FlowerSpring\JumpEven\Throughobserve\willEase\Eye.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}