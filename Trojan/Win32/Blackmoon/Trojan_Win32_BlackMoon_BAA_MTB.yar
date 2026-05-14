
rule Trojan_Win32_BlackMoon_BAA_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 5d e4 83 c3 2c 89 5d d4 8b 5d e4 83 c3 30 89 5d d0 8b 5d e4 83 c3 38 89 5d cc 8b 5d d0 db 03 dd 5d c4 dd 45 c4 8b 5d cc db 03 dd 5d bc dc 45 bc dd 5d b4 dd 45 b4 } //2
		$a_01_1 = {62 6c 61 63 6b 6d 6f 6f 6e } //1 blackmoon
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}