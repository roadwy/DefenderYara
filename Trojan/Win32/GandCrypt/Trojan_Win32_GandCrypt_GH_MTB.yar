
rule Trojan_Win32_GandCrypt_GH_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 69 d2 fd 43 03 00 89 15 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 a0 ?? ?? ?? ?? 30 04 1e 46 3b f7 7c } //1
		$a_02_1 = {3d 4a 38 02 00 7e ?? ba db 86 00 00 66 3b ca 75 ?? 40 3d 59 68 00 00 7c } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}