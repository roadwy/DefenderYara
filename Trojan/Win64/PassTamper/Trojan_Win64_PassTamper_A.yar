
rule Trojan_Win64_PassTamper_A{
	meta:
		description = "Trojan:Win64/PassTamper.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 33 ff ba 00 01 00 00 41 8b ff e8 ?? ?? ?? ?? 48 85 c0 74 ?? 0f 1f 40 00 0f 1f 84 00 00 00 00 00 4c 8b c6 48 8d 8c 24 90 90 00 00 00 ba 00 01 00 00 48 ff c7 } //1
		$a_03_1 = {2e 00 73 00 79 00 73 00 00 00 00 00 4e 00 76 00 4b 00 65 00 72 00 62 00 65 00 6c 00 00 00 00 ?? 00 00 00 00 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 0a 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}