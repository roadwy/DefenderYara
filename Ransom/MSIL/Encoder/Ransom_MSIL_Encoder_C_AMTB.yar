
rule Ransom_MSIL_Encoder_C_AMTB{
	meta:
		description = "Ransom:MSIL/Encoder.C!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {62 6c 65 65 64 69 6e 67 66 75 63 6b 2e 70 64 62 } //bleedingfuck.pdb  1
		$a_80_1 = {2a 62 6c 65 65 64 69 6e 67 66 75 63 6b 2e 62 61 63 6b 67 72 6f 75 6e 64 2b 3c 53 65 74 57 61 6c 6c 70 61 70 65 72 3e } //*bleedingfuck.background+<SetWallpaper>  1
		$a_80_2 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 41 63 74 69 76 65 44 65 73 6b 74 6f 70 } //HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop  1
		$a_80_3 = {68 74 74 70 73 3a 2f 2f 77 69 6d 67 2e 72 75 6c 65 33 34 2e 78 78 78 2f 2f 73 61 6d 70 6c 65 73 2f 35 38 38 2f 73 61 6d 70 6c 65 5f 31 36 36 33 32 35 38 36 32 38 36 32 39 36 31 64 63 34 31 37 61 37 30 39 32 35 38 37 66 37 36 37 34 61 32 37 36 62 65 36 2e 6a 70 67 3f 31 35 30 31 31 31 32 33 } //https://wimg.rule34.xxx//samples/588/sample_166325862862961dc417a7092587f7674a276be6.jpg?15011123  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}