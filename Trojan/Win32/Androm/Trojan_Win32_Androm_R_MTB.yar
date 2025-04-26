
rule Trojan_Win32_Androm_R_MTB{
	meta:
		description = "Trojan:Win32/Androm.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 84 0a 56 c4 08 00 8b 15 [0-04] 88 04 0a 81 c4 74 02 00 00 } //2
		$a_01_1 = {33 ce 33 c1 2b f8 } //1
		$a_01_2 = {33 d7 33 c2 2b f0 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}