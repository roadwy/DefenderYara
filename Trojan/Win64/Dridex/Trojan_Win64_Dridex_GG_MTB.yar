
rule Trojan_Win64_Dridex_GG_MTB{
	meta:
		description = "Trojan:Win64/Dridex.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {6e 61 74 69 76 65 48 73 6c 75 74 49 6e 74 65 72 6e 65 74 43 61 6e 61 72 79 61 6e 64 73 } //nativeHslutInternetCanaryands  01 00 
		$a_80_1 = {70 6c 75 67 2d 69 6e 73 33 73 63 6f 72 65 2e 36 37 77 43 63 61 72 74 6d 61 6e } //plug-ins3score.67wCcartman  01 00 
		$a_80_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 75 73 65 73 66 6c 6f 72 69 64 61 } //Applicationusesflorida  01 00 
		$a_80_3 = {43 6f 6e 63 75 72 72 65 6e 74 6c 79 2c 69 6e 6b 4a 74 72 61 6e 73 6c 61 74 69 6f 6e 46 50 6f 74 68 65 72 } //Concurrently,inkJtranslationFPother  01 00 
		$a_80_4 = {61 6e 64 73 65 63 75 72 69 74 79 76 43 6f 75 72 74 2e 6e } //andsecurityvCourt.n  01 00 
		$a_80_5 = {63 62 72 6f 77 73 65 72 66 4d 6f 7a 69 6c 6c 61 78 64 65 73 6b 74 6f 70 6f 6e 72 } //cbrowserfMozillaxdesktoponr  01 00 
		$a_80_6 = {43 68 72 6f 6d 65 2e 31 36 32 62 72 6f 77 73 65 72 73 2e 32 30 30 38 } //Chrome.162browsers.2008  01 00 
		$a_80_7 = {45 47 6f 6f 67 6c 65 6c 4f 66 66 71 51 4d 6c } //EGooglelOffqQMl  00 00 
	condition:
		any of ($a_*)
 
}