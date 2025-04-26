
rule Trojan_BAT_LokiBot_NYT_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.NYT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 65 39 33 66 64 62 38 61 2d 39 32 61 66 2d 34 39 66 65 2d 39 37 33 35 2d 36 35 34 33 33 66 61 31 30 61 34 32 } //1 $e93fdb8a-92af-49fe-9735-65433fa10a42
		$a_01_1 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 } //1 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resource
		$a_01_2 = {65 4d 61 69 6c 20 45 78 74 72 61 63 74 6f 72 20 76 32 2e 31 72 32 } //1 eMail Extractor v2.1r2
		$a_81_3 = {32 2e 31 72 32 2c 20 c2 a9 20 32 30 30 30 2d 32 30 30 35 20 4d 61 78 70 72 6f 67 } //1
		$a_01_4 = {47 6d 72 61 62 6e 61 65 64 2e 65 78 65 } //1 Gmrabnaed.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}