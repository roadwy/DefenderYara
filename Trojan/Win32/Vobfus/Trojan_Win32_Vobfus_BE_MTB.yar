
rule Trojan_Win32_Vobfus_BE_MTB{
	meta:
		description = "Trojan:Win32/Vobfus.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {a5 58 2f ed a2 4d 98 21 e6 42 3c de bb 2d 6b 4f ad 33 99 66 cf 11 b7 0c 00 aa 00 60 d3 93 4c } //01 00 
		$a_01_1 = {85 55 42 1c 84 46 ad bb 7d 93 aa 54 5a 35 00 77 12 3a 56 fa 69 49 87 86 e5 fc bd d0 96 b0 e7 e5 b0 5a 7e 64 69 43 80 cd 97 c3 1f 21 d5 16 71 } //00 00 
	condition:
		any of ($a_*)
 
}