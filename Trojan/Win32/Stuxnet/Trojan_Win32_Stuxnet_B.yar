
rule Trojan_Win32_Stuxnet_B{
	meta:
		description = "Trojan:Win32/Stuxnet.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {85 c0 75 07 b8 90 01 04 eb 90 01 01 ff d0 8a 96 90 01 02 00 00 90 00 } //1
		$a_01_1 = {c7 45 f4 4d 5a 90 00 c7 45 ec 0b ad fe ed } //1
		$a_03_2 = {8d 45 fc 50 e8 90 01 02 00 00 50 ff d6 85 c0 7d 07 b8 90 01 04 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}