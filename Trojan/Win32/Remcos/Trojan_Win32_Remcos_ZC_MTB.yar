
rule Trojan_Win32_Remcos_ZC_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_02_0 = {5a 8b ca 99 f7 f9 42 8b 45 f8 8a 44 10 ff 32 90 01 03 8d 45 90 00 } //5
		$a_01_1 = {73 65 4d 33 33 45 58 } //1 seM33EX
		$a_01_2 = {58 45 33 33 4d 65 73 } //1 XE33Mes
	condition:
		((#a_02_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}