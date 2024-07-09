
rule Trojan_Win32_GandCrypt_PVB_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.PVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 5c 24 1c 89 33 8b 74 24 18 89 7b 04 81 fe 13 e6 33 00 76 } //1
		$a_02_1 = {89 74 24 18 89 5c 24 1c 3b 74 24 2c 0f 82 ?? ?? ?? ?? 5e 5d 5b 8b 4c 24 44 5f 33 cc e8 ?? ?? ?? ?? 83 c4 44 c2 0c 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}