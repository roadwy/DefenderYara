
rule Trojan_Win32_GandCrypt_PVS_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.PVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f be 19 e8 ?? ?? ?? ?? 33 d8 8b 55 c4 03 55 fc 88 1a eb } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}