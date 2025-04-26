
rule Ransom_Win32_Genasom_KF{
	meta:
		description = "Ransom:Win32/Genasom.KF,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 6b 6f 6e 75 2e 70 68 70 3f 68 77 69 64 3d 00 } //2
		$a_01_1 = {34 47 45 4d 41 20 2d 20 41 75 66 20 49 68 72 65 6d 20 52 65 63 68 6e 65 72 20 77 75 72 64 65 6e 20 52 61 75 62 6b 6f 70 69 65 6e 20 67 65 66 75 6e 64 65 6e } //2 4GEMA - Auf Ihrem Rechner wurden Raubkopien gefunden
		$a_01_2 = {5c 73 74 6e 65 6e 6f 70 6d 6f 43 20 64 65 6c 6c 61 74 73 6e 49 5c 70 75 74 65 53 20 65 76 69 74 63 41 5c 74 66 6f 73 6f 72 63 69 4d 5c 45 52 41 57 54 46 4f 53 } //1 \stnenopmoC dellatsnI\puteS evitcA\tfosorciM\ERAWTFOS
		$a_01_3 = {5c 6e 75 52 5c 6e 6f 69 73 72 65 56 74 6e 65 72 72 75 43 5c 73 77 6f 64 6e 69 57 5c 74 66 6f 73 6f 72 63 69 4d 5c 45 52 41 57 54 46 4f 53 } //1 \nuR\noisreVtnerruC\swodniW\tfosorciM\ERAWTFOS
		$a_01_4 = {50 61 67 65 20 69 73 20 6c 6f 61 64 69 6e 67 2c 20 70 6c 65 61 73 65 20 77 61 69 74 2e 20 54 68 69 73 20 6d 61 79 20 74 61 6b 65 20 75 70 20 74 6f 20 33 30 20 73 65 63 6f 6e 64 73 2e 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}