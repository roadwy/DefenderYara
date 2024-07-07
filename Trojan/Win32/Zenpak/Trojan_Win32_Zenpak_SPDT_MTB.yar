
rule Trojan_Win32_Zenpak_SPDT_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.SPDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {35 36 56 59 65 4d 64 6a 2b 62 75 64 31 79 6e 50 23 5a 58 41 73 67 3d 66 } //2 56VYeMdj+bud1ynP#ZXAsg=f
		$a_01_1 = {42 6f 64 73 75 77 74 75 62 65 73 74 64 48 6e 69 74 } //2 BodsuwtubestdHnit
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}