
rule Trojan_Win32_GandCrypt_AR_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {69 c9 fd 43 03 00 89 0d ?? ?? ?? 00 81 05 ?? ?? ?? 00 c3 9e 26 00 81 3d ?? ?? ?? 00 cf 12 00 00 0f b7 1d ?? ?? ?? 00 75 ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 45 f8 30 1c 06 90 0a 45 00 ff 15 ?? ?? ?? ?? 8b 0d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}