
rule Trojan_Win32_LummaC_BO_MTB{
	meta:
		description = "Trojan:Win32/LummaC.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {31 75 fc 81 3d ?? ?? ?? 00 13 02 00 00 } //3
		$a_03_1 = {c1 e6 04 03 75 ?? 8d 14 0b 33 f2 81 3d } //1
		$a_01_2 = {81 fe 42 71 20 00 7f 09 46 81 fe 12 7d 06 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}