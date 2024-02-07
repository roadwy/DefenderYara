
rule Trojan_Win32_BlackMoon_GMH_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 6c 4d 65 6d 68 72 74 75 61 68 74 65 56 69 68 6c 6f 63 61 68 5a 77 41 6c } //01 00  hlMemhrtuahteVihlocahZwAl
		$a_01_1 = {64 75 6a 6b 5a 41 55 34 37 5a 46 } //01 00  dujkZAU47ZF
		$a_01_2 = {5c 4e 6f 70 2d 41 2e 73 79 73 } //01 00  \Nop-A.sys
		$a_01_3 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 20 45 72 72 6f 72 } //01 00  BlackMoon RunTime Error
		$a_01_4 = {64 75 6a 6b 5a 44 4e 31 32 5a 46 } //00 00  dujkZDN12ZF
	condition:
		any of ($a_*)
 
}