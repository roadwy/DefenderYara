
rule Trojan_BAT_CoinStealer_SK_MTB{
	meta:
		description = "Trojan:BAT/CoinStealer.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {24 31 38 37 62 33 62 31 32 2d 31 38 35 64 2d 34 63 61 38 2d 62 31 39 38 2d 66 38 66 66 66 30 31 30 35 37 32 37 } //1 $187b3b12-185d-4ca8-b198-f8fff0105727
		$a_81_1 = {5c 76 61 6e 69 74 79 67 65 6e 5c 76 61 6e 69 74 79 6b 69 74 74 79 5c 62 74 63 67 65 6e 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 62 74 63 67 65 6e 2e 70 64 62 } //1 \vanitygen\vanitykitty\btcgen\obj\Release\btcgen.pdb
		$a_81_2 = {62 74 63 67 65 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 btcgen.Properties.Resources
		$a_81_3 = {62 74 63 67 65 6e 2e 65 78 65 } //1 btcgen.exe
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}