
rule Trojan_Linux_MsfShellBin_G{
	meta:
		description = "Trojan:Linux/MsfShellBin.G,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 97 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? 51 48 89 e6 6a 10 5a 6a 2a 58 0f 05 59 48 85 c0 79 ?? 49 ff c9 74 ?? 57 6a 23 58 6a ?? 6a ?? 48 89 e7 48 31 f6 0f 05 59 59 5f 48 85 c0 79 ?? 6a 3c 58 6a 01 5f 0f 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}