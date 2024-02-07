
rule Trojan_Win32_AsyncRat_RPZ_MTB{
	meta:
		description = "Trojan:Win32/AsyncRat.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8b f0 ff d6 8d 45 f8 50 8b 45 f8 50 53 8b 45 fc 50 e8 90 01 04 33 c0 5a 59 59 64 89 10 90 00 } //01 00 
		$a_01_1 = {6d 00 79 00 71 00 63 00 6c 00 6f 00 75 00 64 00 2e 00 63 00 6f 00 6d 00 } //01 00  myqcloud.com
		$a_01_2 = {43 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 62 00 69 00 6e 00 } //00 00  Client.bin
	condition:
		any of ($a_*)
 
}