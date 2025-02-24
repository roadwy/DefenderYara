
rule Trojan_Win32_AVTamper_E{
	meta:
		description = "Trojan:Win32/AVTamper.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c4 04 5a 57 81 c7 a4 0f 00 00 81 cf 73 3b 01 00 81 cf 19 08 00 00 81 f7 7e 8a 00 00 5f } //1
		$a_03_1 = {b9 6b 00 00 00 66 89 8d ?? ?? ?? ?? ba 65 00 00 00 66 89 95 ?? ?? ?? ?? b8 72 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}