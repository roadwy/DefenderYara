
rule TrojanDownloader_BAT_Genmaldow_W{
	meta:
		description = "TrojanDownloader:BAT/Genmaldow.W,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {55 73 65 72 73 5c 52 6f 6f 63 6b 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 52 65 76 69 76 65 6c 5c 52 65 76 69 76 65 6c 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 } //1 Users\Roock\source\repos\Revivel\Revivel\obj\Release
		$a_01_1 = {76 32 2e 30 2e 35 30 37 32 37 } //1 v2.0.50727
		$a_01_2 = {52 65 61 6c 41 6e 64 47 6f 6f 64 } //1 RealAndGood
		$a_01_3 = {4f 62 69 65 54 72 69 63 65 } //1 ObieTrice
		$a_01_4 = {53 6c 6f 77 65 72 47 6f 64 6c } //1 SlowerGodl
		$a_01_5 = {53 74 6f 70 4d 61 6b 69 6e 67 } //1 StopMaking
		$a_01_6 = {52 61 62 61 74 } //1 Rabat
		$a_01_7 = {46 6c 65 73 68 } //1 Flesh
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=5
 
}