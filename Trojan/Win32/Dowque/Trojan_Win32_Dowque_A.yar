
rule Trojan_Win32_Dowque_A{
	meta:
		description = "Trojan:Win32/Dowque.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 09 00 06 00 00 03 00 "
		
	strings :
		$a_02_0 = {ff ff 8b d8 83 fb ff 0f 84 90 01 02 00 00 6a 02 6a 00 6a fc 53 e8 90 00 } //03 00 
		$a_02_1 = {6a 00 8d 45 f8 50 6a 04 8d 45 f4 50 53 e8 90 01 03 ff 81 75 90 00 } //03 00 
		$a_00_2 = {8b d8 83 fb 01 7c 66 8d 45 f0 50 8b cb 49 ba 01 00 00 00 8b 45 ec } //01 00 
		$a_00_3 = {7b 41 36 30 31 31 46 38 46 2d 41 37 46 38 2d 34 39 41 41 2d 39 41 44 41 2d 34 39 31 32 37 44 34 33 31 33 38 46 7d } //01 00  {A6011F8F-A7F8-49AA-9ADA-49127D43138F}
		$a_00_4 = {46 69 6c 65 73 5c 4d 69 63 72 6f 73 6f 66 74 20 53 68 61 72 65 64 5c 4d 53 49 4e 46 4f } //01 00  Files\Microsoft Shared\MSINFO
		$a_00_5 = {48 54 54 50 2f 31 2e 30 } //00 00  HTTP/1.0
	condition:
		any of ($a_*)
 
}