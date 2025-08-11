
rule Trojan_Win32_Rhadamanthys_GVB_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 fe 81 ef 89 15 00 00 03 c7 31 03 83 45 ec 04 6a 00 } //2
		$a_01_1 = {33 c0 8b 55 ec 01 13 8b 75 d4 03 75 a4 03 75 ec 03 f0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}