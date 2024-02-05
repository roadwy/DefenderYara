
rule Ransom_Win32_DelShad_SC_MTB{
	meta:
		description = "Ransom:Win32/DelShad.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {59 00 6f 00 75 00 72 00 90 02 15 68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 90 00 } //01 00 
		$a_02_1 = {59 6f 75 72 90 02 15 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 90 00 } //01 00 
		$a_80_2 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //@protonmail.com  01 00 
		$a_80_3 = {65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 20 6f 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 } //encrypted files on your computer  01 00 
		$a_80_4 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //CryptEncrypt  01 00 
		$a_80_5 = {43 72 79 70 74 41 63 71 75 69 72 65 43 6f 6e 74 65 78 74 41 } //CryptAcquireContextA  00 00 
	condition:
		any of ($a_*)
 
}