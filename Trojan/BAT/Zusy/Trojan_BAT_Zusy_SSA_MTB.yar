
rule Trojan_BAT_Zusy_SSA_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SSA!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 31 30 33 2e 31 31 36 2e 31 30 35 2e 39 30 2f 6b 79 75 63 31 2f } //1 http://103.116.105.90/kyuc1/
		$a_01_1 = {73 6f 32 67 61 6d 65 5f 6c 69 74 65 2e 65 78 65 } //1 so2game_lite.exe
		$a_01_2 = {41 00 75 00 74 00 6f 00 75 00 70 00 64 00 61 00 74 00 65 00 5f 00 62 00 61 00 6b 00 2e 00 65 00 78 00 65 00 } //1 Autoupdate_bak.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}