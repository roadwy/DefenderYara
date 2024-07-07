
rule Trojan_Win32_Startpage_SE{
	meta:
		description = "Trojan:Win32/Startpage.SE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 6e 61 62 6c 65 64 00 68 6f 74 54 72 61 63 6b 69 6e 67 00 4d 75 6c 74 69 53 65 6c 65 63 74 00 } //1 湅扡敬d潨呴慲正湩g畍瑬卩汥捥t
		$a_02_1 = {8d 4d bc e9 90 01 04 ff d7 8b d0 8d 8d 2c fe ff ff e9 90 01 04 89 8d 34 fb ff ff e9 90 01 04 8b 48 0c 8b 85 34 fb ff ff 90 00 } //1
		$a_02_2 = {88 04 3a 8b 45 dc e9 90 01 04 8d 8d 30 ff ff ff ff d6 8b 95 78 fc ff ff e9 90 01 04 8d 55 ec 6a 01 52 56 e9 90 00 } //1
		$a_02_3 = {6a 00 6a 01 6a 01 8d 85 ec fd ff ff 6a 00 50 6a 10 68 80 08 00 00 ff 15 90 01 04 8b 4d 98 8b 85 ec fd ff ff 83 c1 04 c7 85 dc fd ff ff 90 01 04 89 8d e4 fd ff ff 8b 48 14 c1 e1 04 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}