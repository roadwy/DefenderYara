
rule Trojan_Win32_Stuxnet_B{
	meta:
		description = "Trojan:Win32/Stuxnet.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {85 c0 75 07 b8 ?? ?? ?? ?? eb ?? ff d0 8a 96 ?? ?? 00 00 } //1
		$a_01_1 = {c7 45 f4 4d 5a 90 00 c7 45 ec 0b ad fe ed } //1
		$a_03_2 = {8d 45 fc 50 e8 ?? ?? 00 00 50 ff d6 85 c0 7d 07 b8 ?? ?? ?? ?? eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}