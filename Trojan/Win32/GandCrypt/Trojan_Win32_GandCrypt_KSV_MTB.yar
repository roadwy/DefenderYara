
rule Trojan_Win32_GandCrypt_KSV_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.KSV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {69 c0 fd 43 03 00 53 05 c3 9e 26 00 53 a3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a0 ?? ?? ?? ?? 30 04 3e 46 3b 75 08 7c } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}