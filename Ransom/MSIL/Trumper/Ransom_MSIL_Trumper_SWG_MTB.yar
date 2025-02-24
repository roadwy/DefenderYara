
rule Ransom_MSIL_Trumper_SWG_MTB{
	meta:
		description = "Ransom:MSIL/Trumper.SWG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_80_0 = {59 6f 75 72 20 4d 42 52 20 68 61 73 20 62 65 65 6e 20 6f 76 65 72 77 72 69 74 74 65 64 20 61 6e 64 20 79 6f 75 72 20 66 69 6c 65 73 20 65 6e 63 72 79 70 74 65 64 } //Your MBR has been overwritted and your files encrypted  2
		$a_80_1 = {63 6f 6e 74 61 63 74 20 6d 65 20 6f 6e 20 74 65 6c 65 67 72 61 6d 20 68 74 74 70 73 3a 2f 2f 74 2e 6d 65 2f 73 68 33 64 64 64 64 20 74 6f 20 67 65 74 20 79 6f 75 72 20 66 69 6c 65 73 20 62 61 63 6b } //contact me on telegram https://t.me/sh3dddd to get your files back  2
		$a_01_2 = {24 61 62 33 64 30 62 63 62 2d 36 35 65 31 2d 34 38 38 66 2d 39 31 65 33 2d 66 39 34 61 61 35 32 38 63 62 31 61 } //1 $ab3d0bcb-65e1-488f-91e3-f94aa528cb1a
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}