
rule Trojan_Win32_GandCrypt_GE_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 69 c0 fd 43 03 00 56 a3 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 81 3d ?? ?? ?? ?? a5 02 00 00 8b 35 ?? ?? ?? ?? 75 } //1
		$a_02_1 = {50 6a 00 ff d7 81 fe 4a 38 02 00 7e ?? b9 db 86 00 00 66 3b d9 75 ?? 46 81 fe 36 9c 97 01 7c } //1
		$a_02_2 = {33 f6 85 ff 7e ?? 53 81 ff 69 04 00 00 75 ?? 6a 00 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 00 ff 15 } //1
		$a_00_3 = {30 04 1e 46 3b f7 7c } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=2
 
}