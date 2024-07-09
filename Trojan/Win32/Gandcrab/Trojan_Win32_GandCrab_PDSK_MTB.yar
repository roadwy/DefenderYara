
rule Trojan_Win32_GandCrab_PDSK_MTB{
	meta:
		description = "Trojan:Win32/GandCrab.PDSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {fd 43 03 00 6a 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? ff 15 } //2
		$a_02_1 = {8b 4d 08 a0 ?? ?? ?? ?? 30 04 0e 46 3b f7 7c } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}