
rule Trojan_Win32_BlackMoon_GNX_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.GNX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 d4 68 00 00 00 00 68 48 00 00 00 ff 75 e4 ff 75 d4 ff 75 fc 33 c0 ff 15 ?? ?? ?? ?? ?? ?? 68 3c 00 00 00 ff 75 e4 e8 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}