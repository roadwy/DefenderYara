
rule Trojan_Win32_GandCrypt_PVG_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.PVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {69 c0 fd 43 03 00 57 05 c3 9e 26 00 57 a3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a0 ?? ?? ?? ?? 30 04 1e 46 3b 75 08 7c } //2
		$a_02_1 = {56 8b 45 08 8d 34 07 e8 ?? ?? ?? ?? 30 06 47 3b 7d 0c 7c ?? 5e } //1
		$a_02_2 = {8b 4d fc 33 cd 25 ff 7f 00 00 e8 ?? ?? ?? ?? c9 c3 90 09 07 00 0f b7 05 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}