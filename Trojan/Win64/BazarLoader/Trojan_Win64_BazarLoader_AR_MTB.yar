
rule Trojan_Win64_BazarLoader_AR_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_80_0 = {50 c7 44 24 04 00 00 00 00 b8 b0 7a 01 00 48 03 05 23 20 00 00 41 5a 48 ff e0 } //P�D$  10
		$a_80_1 = {4d 65 68 65 78 64 6e 59 62 77 65 63 67 6e 68 67 74 } //MehexdnYbwecgnhgt  3
		$a_80_2 = {52 77 74 7a 75 63 71 68 47 6d 64 74 6f 66 6e 70 79 7a 61 63 } //RwtzucqhGmdtofnpyzac  3
		$a_80_3 = {59 64 74 79 6a 6c 79 6e 76 71 77 52 6e 76 67 68 6a 66 78 } //YdtyjlynvqwRnvghjfx  3
		$a_80_4 = {5a 75 71 78 61 6b 77 6e 70 5a 61 78 62 69 6c 76 68 7a 63 70 56 63 69 6b 69 6d 69 76 66 } //ZuqxakwnpZaxbilvhzcpVcikimivf  3
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}