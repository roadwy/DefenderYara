
rule Trojan_Win64_Convagent_NG_MTB{
	meta:
		description = "Trojan:Win64/Convagent.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 84 7d 01 00 00 8b 16 48 8b 00 48 c7 04 d0 ?? ?? ?? ?? e9 f9 fe ff ff 45 31 c0 ba ?? ?? ?? ?? 48 8d 0d 87 f4 09 00 e8 6f 22 00 00 81 38 ?? ?? ?? ?? 48 89 05 da 7c 0c } //5
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 65 70 20 62 79 70 61 73 73 20 2d 77 20 68 69 64 64 65 6e 20 2d 65 } //1 powershell -ep bypass -w hidden -e
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}