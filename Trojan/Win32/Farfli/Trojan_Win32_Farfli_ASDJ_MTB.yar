
rule Trojan_Win32_Farfli_ASDJ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ASDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 8a 14 11 32 94 ?? ?? ff ff ff 8b 85 ?? ?? ff ff 25 ff ?? ?? ?? 8b 4d 08 88 14 01 } //3
		$a_01_1 = {53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 73 6f 75 67 6f 75 } //2 SystemRoot%\System32\svchost.exe -k sougou
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}