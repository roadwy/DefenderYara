
rule Trojan_Win32_Pony_DA_MTB{
	meta:
		description = "Trojan:Win32/Pony.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 68 a1 05 00 00 6a 00 ff d0 } //1
		$a_03_1 = {10 30 00 10 90 02 10 a1 05 00 00 8a 90 01 02 90 03 01 01 34 80 90 02 03 88 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}