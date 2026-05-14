
rule Trojan_BAT_RedLineStealer_AMTB{
	meta:
		description = "Trojan:BAT/RedLineStealer!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_80_0 = {46 6f 72 43 72 79 70 74 2e 65 78 65 } //ForCrypt.exe  2
		$a_80_1 = {43 3a 5c 55 73 65 72 73 5c 73 74 34 69 6e 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 46 6f 72 43 72 79 70 74 5c 6f 62 6a 5c 44 65 62 75 67 5c 46 6f 72 43 72 79 70 74 2e 70 64 62 } //C:\Users\st4in\source\repos\ForCrypt\obj\Debug\ForCrypt.pdb  2
		$a_80_2 = {24 62 36 66 61 30 37 31 33 2d 63 65 61 32 2d 34 34 65 34 2d 38 63 62 61 2d 62 31 63 32 39 38 62 30 30 61 38 39 } //$b6fa0713-cea2-44e4-8cba-b1c298b00a89  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1) >=5
 
}