
rule Trojan_Win32_MemCrypt_MK_MTB{
	meta:
		description = "Trojan:Win32/MemCrypt.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {4d 45 4d 5a 20 54 72 6f 6a 61 6e } //MEMZ Trojan  01 00 
		$a_80_1 = {44 6f 6e 27 74 20 6b 69 6c 6c 20 6d 79 20 74 72 6f 6a 61 6e } //Don't kill my trojan  01 00 
		$a_80_2 = {79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 66 75 63 6b 65 64 20 62 79 20 6d 65 } //your computer fucked by me  01 00 
		$a_80_3 = {59 6f 75 20 63 61 6e 27 74 20 72 65 62 6f 6f 74 } //You can't reboot  01 00 
		$a_80_4 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 77 6f 6e 27 74 20 62 6f 6f 74 20 75 70 20 61 67 61 69 6e } //Your computer won't boot up again  00 00 
		$a_00_5 = {5d 04 00 } //00 c6 
	condition:
		any of ($a_*)
 
}