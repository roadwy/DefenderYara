
rule Trojan_Win32_CryptInject_VDSK_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.VDSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 f4 8b cb c1 e9 05 03 c3 03 4d e8 33 c8 c7 05 ?? ?? ?? ?? f4 6e e0 f7 33 4d fc 2b f9 81 fe d9 02 00 00 75 23 } //2
		$a_00_1 = {88 54 24 11 8a d6 80 e2 f0 88 74 24 10 c0 e2 02 0a 14 18 88 54 24 12 8a d6 80 e2 fc c0 e2 04 0a 54 18 01 88 54 24 13 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2) >=2
 
}