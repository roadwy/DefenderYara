
rule Trojan_Win32_Pony_AU_MTB{
	meta:
		description = "Trojan:Win32/Pony.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {b1 f1 86 16 6a 31 44 33 70 07 91 01 1b b8 9e 3b 75 49 ad fa 88 70 15 d4 40 80 72 60 f8 1d d2 c1 5d 51 98 a9 65 04 03 85 7c } //02 00 
		$a_01_1 = {b4 c4 d9 65 05 b7 97 64 dc 73 a4 05 a2 1c 61 12 aa 2d fd 24 e5 96 84 b1 1f d1 4a 33 ac a0 db 56 de 0a 5c 32 04 7d 37 a7 0f f7 43 dd 96 e5 25 2d b5 21 23 b9 d8 d9 bc 5e 70 } //00 00 
	condition:
		any of ($a_*)
 
}