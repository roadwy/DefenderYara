
rule Trojan_Win32_Injector_YF_bit{
	meta:
		description = "Trojan:Win32/Injector.YF!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 04 58 69 c0 [0-04] 8b 4d dc c7 04 01 [0-04] 6a 04 58 69 c0 [0-04] 8b 4d dc c7 04 01 [0-04] 6a 04 58 69 c0 [0-04] 8b 4d dc c7 04 01 } //1
		$a_03_1 = {0b c0 74 02 ff e0 68 ?? ?? ?? ?? b8 ?? ?? ?? ?? ff d0 ff e0 } //1
		$a_01_2 = {8b 45 08 8b 00 ff 75 08 ff 50 08 8b 45 fc 8b 4d ec 64 89 0d 00 00 00 00 5f 5e 5b c9 c2 04 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}