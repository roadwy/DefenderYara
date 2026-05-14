
rule Trojan_Win64_ClawHavoc_GZ_MTB{
	meta:
		description = "Trojan:Win64/ClawHavoc.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 f9 03 0f 85 9a 00 00 00 48 8b b0 98 fd ff ff 48 3b b0 a8 fd ff ff 0f 84 e5 01 00 00 48 8d 8e 88 00 00 00 48 89 88 98 fd ff ff b9 88 } //2
		$a_00_1 = {41 00 75 00 74 00 6f 00 6d 00 61 00 74 00 69 00 63 00 20 00 68 00 61 00 72 00 64 00 77 00 61 00 72 00 65 00 20 00 64 00 72 00 69 00 76 00 65 00 72 00 20 00 75 00 70 00 64 00 61 00 74 00 65 00 20 00 74 00 6f 00 6f 00 6c 00 } //1 Automatic hardware driver update tool
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1) >=3
 
}