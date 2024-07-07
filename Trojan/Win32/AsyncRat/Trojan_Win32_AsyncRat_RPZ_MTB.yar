
rule Trojan_Win32_AsyncRat_RPZ_MTB{
	meta:
		description = "Trojan:Win32/AsyncRat.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d6 ff b5 98 fb ff ff ff d6 0f 57 c0 c7 85 ec fb ff ff 00 00 00 00 8d 95 c0 fb ff ff 66 0f d6 85 e4 fb ff ff 8d 8d e4 fb ff ff e8 90 01 04 c6 45 fc 04 8b 85 e8 fb ff ff 2b 85 e4 fb ff ff 6a 40 68 00 10 00 00 50 6a 00 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_AsyncRat_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/AsyncRat.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8b f0 ff d6 8d 45 f8 50 8b 45 f8 50 53 8b 45 fc 50 e8 90 01 04 33 c0 5a 59 59 64 89 10 90 00 } //1
		$a_01_1 = {6d 00 79 00 71 00 63 00 6c 00 6f 00 75 00 64 00 2e 00 63 00 6f 00 6d 00 } //1 myqcloud.com
		$a_01_2 = {43 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 62 00 69 00 6e 00 } //1 Client.bin
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}