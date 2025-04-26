
rule Ransom_Win32_GandCrab_SB_MTB{
	meta:
		description = "Ransom:Win32/GandCrab.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 65 72 6e 73 74 65 69 6e 20 6c 65 74 27 73 20 64 61 6e 63 65 20 73 61 6c 73 61 } //1 Bernstein let's dance salsa
		$a_01_1 = {70 61 73 73 20 47 61 6e 64 43 72 61 62 } //1 pass GandCrab
		$a_00_2 = {4b 00 52 00 41 00 42 00 2d 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 2e 00 68 00 74 00 6d 00 6c 00 } //1 KRAB-DECRYPT.html
		$a_00_3 = {4b 00 52 00 41 00 42 00 2d 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 2e 00 74 00 78 00 74 00 } //1 KRAB-DECRYPT.txt
		$a_00_4 = {62 00 6f 00 6f 00 74 00 73 00 65 00 63 00 74 00 2e 00 62 00 61 00 6b 00 } //1 bootsect.bak
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}