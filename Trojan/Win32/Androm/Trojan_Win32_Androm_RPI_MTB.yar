
rule Trojan_Win32_Androm_RPI_MTB{
	meta:
		description = "Trojan:Win32/Androm.RPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 6c 8b 74 24 2c 8b 7c 24 20 03 c6 89 44 24 14 8a 00 88 44 24 27 8b c7 } //1
		$a_01_1 = {0f af ca 0f af ce 0f af cf 0f af 4c 24 50 8b f9 89 7c 24 20 8a 8c 24 80 00 00 00 32 4c 24 27 3b c3 88 4c 24 27 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}