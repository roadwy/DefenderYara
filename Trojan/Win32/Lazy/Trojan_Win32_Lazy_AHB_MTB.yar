
rule Trojan_Win32_Lazy_AHB_MTB{
	meta:
		description = "Trojan:Win32/Lazy.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 98 03 45 a4 d1 e8 89 45 8c 8b 45 c8 8b 4d e0 03 48 20 8b 55 8c 8b 04 91 89 45 80 8b 45 e0 03 45 80 89 85 74 ff ff ff 8b 45 ec 89 85 88 fe ff ff 8b 8d 74 ff ff ff } //3
		$a_01_1 = {8b 45 04 89 85 e8 fd ff ff 8d 45 04 89 85 f4 fd ff ff c7 85 30 fd ff ff 01 00 01 00 8b 40 fc 89 85 e4 fd ff ff 8b 45 0c 89 85 e0 fc ff ff 8b 45 10 89 85 e4 fc ff ff 8b 45 04 89 85 ec fc ff ff ff 15 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}