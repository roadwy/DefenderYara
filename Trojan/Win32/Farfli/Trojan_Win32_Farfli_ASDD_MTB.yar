
rule Trojan_Win32_Farfli_ASDD_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ASDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 55 f0 8b 55 0c 03 55 e8 8b 45 08 03 45 f0 8a 0a 32 08 8b 55 0c 03 55 e8 88 0a e9 } //1
		$a_03_1 = {ff 43 c6 85 90 02 02 ff ff 6f c6 85 90 02 02 ff ff 6e c6 85 90 02 02 ff ff 6e c6 85 90 02 02 ff ff 65 c6 85 90 02 02 ff ff 63 c6 85 90 02 02 ff ff 74 c6 85 90 02 02 ff ff 47 c6 85 90 02 02 ff ff 72 c6 85 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}