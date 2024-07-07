
rule Trojan_Win64_CobaltStrikeShellcode_CC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrikeShellcode.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {e6 97 a0 e6 b3 95 e6 89 93 e5 bc 80 e9 85 8d e7 bd ae e6 96 87 e4 bb b6 e3 80 82 0a 00 e8 af bb e5 8f 96 53 68 65 6c 6c 63 6f 64 65 } //1
		$a_01_1 = {b1 e8 b4 a5 e3 80 82 0a 00 e5 86 85 e5 ad 98 e5 88 86 e9 85 8d e5 a4 b1 e8 b4 a5 e3 80 82 0a } //1
		$a_01_2 = {e6 97 a0 e6 b3 95 e4 b8 ba 53 68 65 6c 6c 63 6f 64 65 e5 88 86 e9 85 8d e5 86 85 e5 ad 98 e3 80 82 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}