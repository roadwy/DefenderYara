
rule Trojan_Linux_SAgnt_R_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.R!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 e8 7c af fe ff 8b 00 83 f8 73 0f 94 c0 c9 c3 } //1
		$a_03_1 = {48 89 c7 e8 9d 0d 00 00 83 45 c4 01 8b 45 c4 3b 85 1c ff ff ff 0f 9c c0 84 c0 0f ?? ?? ?? ?? ?? 48 81 c4 f0 00 00 00 5b 41 5c c9 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}