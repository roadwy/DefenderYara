
rule Trojan_Win32_VBClone_GZT_MTB{
	meta:
		description = "Trojan:Win32/VBClone.GZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {6b 4d 4e 94 b2 59 59 34 b1 66 2a 1a 96 c9 80 53 01 2f eb } //10
		$a_80_1 = {4b 61 77 61 69 69 2d 55 6e 69 63 6f 72 6e } //Kawaii-Unicorn  1
	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}