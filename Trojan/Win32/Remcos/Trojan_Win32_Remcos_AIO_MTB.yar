
rule Trojan_Win32_Remcos_AIO_MTB{
	meta:
		description = "Trojan:Win32/Remcos.AIO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 85 2c ff ff ff 2b 84 15 60 fb ff ff 89 85 2c ff ff ff 8b 4d e8 83 e9 01 89 4d e8 8b 95 fc fe ff ff 83 c2 01 89 95 fc fe ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}