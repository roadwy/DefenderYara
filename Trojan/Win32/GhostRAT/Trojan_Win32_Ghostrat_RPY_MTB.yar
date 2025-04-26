
rule Trojan_Win32_Ghostrat_RPY_MTB{
	meta:
		description = "Trojan:Win32/Ghostrat.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d 85 f8 fe ff ff eb 03 8d 49 00 8a 10 3a 11 75 1a 84 d2 74 12 8a 50 01 3a 51 01 75 0e 83 c0 02 83 c1 02 84 d2 75 e4 33 c0 eb 05 1b c0 83 d8 ff 85 c0 74 13 8d 95 d4 fe ff ff 52 56 e8 } //1
		$a_01_1 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 explorer.exe
		$a_01_2 = {43 68 65 63 6b 53 65 72 76 65 72 5c 54 63 73 2e 65 78 65 } //1 CheckServer\Tcs.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}