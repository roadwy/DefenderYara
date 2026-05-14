
rule Trojan_Win32_Cerbu_BAB_MTB{
	meta:
		description = "Trojan:Win32/Cerbu.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 95 10 fb ff ff 8b 85 10 fb ff ff 8b 8c 95 84 fd ff ff 2b 8c 85 80 fd ff ff 2b 8d ac fb ff ff 8b 95 10 fb ff ff 8b 85 6c ff ff ff 89 0c 90 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}