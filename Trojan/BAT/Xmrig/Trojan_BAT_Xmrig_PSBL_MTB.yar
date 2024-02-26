
rule Trojan_BAT_Xmrig_PSBL_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.PSBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 61 64 64 69 6e 67 4d 6f 64 65 } //01 00  PaddingMode
		$a_01_1 = {43 72 79 70 74 6f 53 74 72 65 61 6d 4d 6f 64 65 } //01 00  CryptoStreamMode
		$a_01_2 = {43 69 70 68 65 72 4d 6f 64 65 } //02 00  CipherMode
		$a_01_3 = {5f 34 53 7a 4c 6b 6e 47 61 4d 4b 61 63 36 54 53 34 41 76 55 6d 58 6b 46 70 57 4c 65 } //02 00  _4SzLknGaMKac6TS4AvUmXkFpWLe
		$a_01_4 = {5f 39 41 55 35 41 55 69 63 72 49 45 6d 36 54 74 53 4a 6f 76 44 57 4b 34 71 58 4c 65 } //02 00  _9AU5AUicrIEm6TtSJovDWK4qXLe
		$a_01_5 = {5f 66 65 65 37 61 6a 49 51 6a 7a 44 78 38 55 35 68 6a 7a 42 71 31 43 38 75 70 58 65 } //02 00  _fee7ajIQjzDx8U5hjzBq1C8upXe
		$a_01_6 = {5f 36 6a 6e 75 43 7a 79 78 46 5a 41 31 4c 57 77 45 55 36 39 6e 57 62 58 41 46 59 65 } //02 00  _6jnuCzyxFZA1LWwEU69nWbXAFYe
		$a_01_7 = {49 6c 4b 64 44 72 43 76 4f 53 78 53 64 54 43 4a 61 4b 41 59 79 70 62 65 } //00 00  IlKdDrCvOSxSdTCJaKAYypbe
	condition:
		any of ($a_*)
 
}