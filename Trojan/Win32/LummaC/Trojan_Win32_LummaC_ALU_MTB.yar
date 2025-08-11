
rule Trojan_Win32_LummaC_ALU_MTB{
	meta:
		description = "Trojan:Win32/LummaC.ALU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 00 89 85 a8 df ff ff 8d 85 00 de ff ff 89 8d ac df ff ff c5 fd 7f 85 40 de ff ff c5 f8 28 8d 60 de ff ff c5 f0 57 8d a0 df ff ff 6a 00 6a 01 c5 f8 29 8d 60 de ff ff 50 c5 f8 77 } //2
		$a_03_1 = {6a 00 50 8d 85 d8 df ff ff 50 8d 8d 88 de ff ff e8 ?? ?? ?? ?? 8d 85 3c df ff ff 50 68 00 20 00 00 8d 85 d8 df ff ff 50 56 ff d7 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}