
rule Trojan_Win32_Barys_AHB_MTB{
	meta:
		description = "Trojan:Win32/Barys.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 c3 f7 f7 8a 01 88 45 ff 46 8b da 8d 84 9d f8 fb ff ff 8b 10 89 11 0f b6 4d ff 89 08 3b f7 72 c6 } //3
		$a_01_1 = {f8 8b 01 03 c2 33 d2 f7 75 18 8a 84 95 f8 fb ff ff 30 07 ff 45 f8 8b 45 f8 3b 45 0c 72 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}