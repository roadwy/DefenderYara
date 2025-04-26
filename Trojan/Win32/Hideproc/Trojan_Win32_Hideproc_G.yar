
rule Trojan_Win32_Hideproc_G{
	meta:
		description = "Trojan:Win32/Hideproc.G,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 00 3c 00 61 00 63 00 63 00 65 00 73 00 73 00 2d 00 64 00 65 00 6e 00 69 00 65 00 64 00 3e 00 00 00 } //1
		$a_03_1 = {83 c4 0c be a2 00 00 00 56 6a 10 5a 8d 4d f0 e8 ?? ?? ?? ?? 81 7d f0 6d d0 4e a2 75 3b 8b 45 f4 39 45 0c 7c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}