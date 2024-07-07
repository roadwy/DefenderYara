
rule Trojan_Win32_StealerGen_DKL_MTB{
	meta:
		description = "Trojan:Win32/StealerGen.DKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_80_0 = {6e 43 6f 74 65 63 75 62 75 6a 69 79 65 73 6f 68 20 70 65 70 65 76 6f 20 66 75 6c 61 79 75 77 69 62 75 78 61 62 65 20 74 65 6d 61 6b 65 6e 61 62 75 62 } //nCotecubujiyesoh pepevo fulayuwibuxabe temakenabub  2
		$a_80_1 = {7a 6f 76 75 67 61 6a 6f 64 75 72 69 63 65 70 65 79 6f 73 6f 66 61 68 69 77 65 6e 61 79 6f 6d 75 } //zovugajoduricepeyosofahiwenayomu  2
		$a_80_2 = {72 50 65 68 61 79 75 76 69 76 69 74 75 78 6f 20 72 75 78 61 67 61 77 69 6a 75 64 20 62 75 7a 75 73 20 70 69 74 75 6e 61 62 61 20 70 69 67 65 6d 75 79 6f 74 } //rPehayuvivituxo ruxagawijud buzus pitunaba pigemuyot  2
		$a_80_3 = {50 75 66 75 79 6f 72 61 6d 75 68 69 76 69 68 20 63 6f 66 6f 78 6f 6c 61 77 61 72 20 68 6f 63 61 67 } //Pufuyoramuhivih cofoxolawar hocag  2
		$a_80_4 = {67 69 70 65 76 75 72 6f 63 6f 66 } //gipevurocof  2
		$a_80_5 = {6d 65 63 61 68 75 73 61 78 65 70 6f 62 75 79 69 7a 61 6a 69 72 } //mecahusaxepobuyizajir  2
		$a_80_6 = {56 69 64 69 7a 6f 74 69 6e 61 20 74 75 66 75 72 69 6e 75 67 20 77 61 72 69 78 6f 6c 65 66 75 6c 69 67 } //Vidizotina tufurinug warixolefulig  2
		$a_80_7 = {59 4f 4e 41 4d 49 4b 4f 52 55 46 45 4e 49 } //YONAMIKORUFENI  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2+(#a_80_7  & 1)*2) >=16
 
}