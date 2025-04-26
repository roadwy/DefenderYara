
rule Trojan_Win32_GCleaner_AGE_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.AGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 28 0d b0 98 43 00 66 0f ef c8 0f 11 09 0f 1f 40 00 80 34 08 2e 40 83 f8 1c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_GCleaner_AGE_MTB_2{
	meta:
		description = "Trojan:Win32/GCleaner.AGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 7d c4 10 8d 45 b0 6a 01 0f 43 45 b0 6a 00 6a 03 ff 73 40 ff 73 3c 6a 50 50 57 ff 15 } //2
		$a_03_1 = {50 8b 03 03 47 28 68 e8 03 00 00 50 ff b5 c4 fe ff ff ff 15 ?? ?? ?? ?? 8b 95 e0 fe ff ff 01 13 89 85 b4 fe ff ff 8b 06 8b c8 2b 0b 81 f9 e8 } //1
		$a_01_2 = {31 38 35 2e 31 35 36 2e 37 33 2e 37 33 } //5 185.156.73.73
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*5) >=8
 
}