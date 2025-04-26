
rule Trojan_Win32_GandCrypt_PVR_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.PVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {69 c9 fd 43 03 00 6a 00 81 c1 c3 9e 26 00 6a 00 89 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 30 14 3e 46 3b f3 7c } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}