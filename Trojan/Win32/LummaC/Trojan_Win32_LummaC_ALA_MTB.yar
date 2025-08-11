
rule Trojan_Win32_LummaC_ALA_MTB{
	meta:
		description = "Trojan:Win32/LummaC.ALA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {f7 d6 33 1d 9c 2d 48 00 c1 c9 0d c1 ce 12 c1 c6 12 c1 c1 0d f7 d6 01 35 29 29 48 00 c7 05 87 28 48 00 a4 ff b0 51 4f c1 cb 1a 40 33 ca f7 de ff 15 } //3
		$a_03_1 = {c1 c6 0d 2b 1d 4b 07 48 00 09 05 5a 28 48 00 43 e8 ?? ?? ?? ?? c1 e0 15 33 d2 f7 d6 ff c9 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*1) >=4
 
}