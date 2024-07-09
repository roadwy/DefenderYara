
rule Trojan_Win32_Pony_DA_MTB{
	meta:
		description = "Trojan:Win32/Pony.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 68 a1 05 00 00 6a 00 ff d0 } //1
		$a_03_1 = {10 30 00 10 [0-10] a1 05 00 00 8a ?? ?? (34|80) [0-03] 88 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}