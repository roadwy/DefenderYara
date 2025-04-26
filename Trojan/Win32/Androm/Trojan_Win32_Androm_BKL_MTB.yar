
rule Trojan_Win32_Androm_BKL_MTB{
	meta:
		description = "Trojan:Win32/Androm.BKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {be a5 15 4f 0b 1c 09 30 65 89 7a f4 3c 91 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Androm_BKL_MTB_2{
	meta:
		description = "Trojan:Win32/Androm.BKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 ec 04 0f b6 10 32 55 e4 88 10 83 45 f4 01 } //1
		$a_01_1 = {8b 45 e8 89 45 e4 8b 45 e4 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}