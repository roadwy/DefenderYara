
rule Trojan_Win32_GandCrab_GD_MTB{
	meta:
		description = "Trojan:Win32/GandCrab.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 34 07 e8 ?? ?? ?? ?? 30 06 47 3b 7c 24 ?? 7c 90 09 04 00 8b 44 24 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}