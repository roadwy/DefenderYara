
rule Trojan_Win32_Offloader_GKP_MTB{
	meta:
		description = "Trojan:Win32/Offloader.GKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 b2 35 00 ?? ?? ?? ?? be 41 0e 00 00 e4 0c 00 ?? ?? ?? ?? 00 00 01 00 0d 00 40 40 } //4
		$a_03_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 60 33 00 ?? ?? ?? ?? 3a 46 0e 00 00 e8 0c 00 ?? ?? ?? ?? 00 00 01 00 0d 00 40 40 } //4
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*4) >=4
 
}