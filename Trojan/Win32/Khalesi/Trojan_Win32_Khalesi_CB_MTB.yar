
rule Trojan_Win32_Khalesi_CB_MTB{
	meta:
		description = "Trojan:Win32/Khalesi.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 18 01 f1 40 b9 90 02 04 01 f1 39 f8 75 d5 90 00 } //2
		$a_01_1 = {31 07 41 01 c9 81 c7 01 00 00 00 39 f7 75 e7 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}