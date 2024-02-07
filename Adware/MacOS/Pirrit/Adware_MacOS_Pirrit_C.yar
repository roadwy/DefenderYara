
rule Adware_MacOS_Pirrit_C{
	meta:
		description = "Adware:MacOS/Pirrit.C,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {80 35 33 53 02 00 b1 80 35 2d 53 02 00 f7 80 35 27 53 02 00 1b } //01 00 
		$a_01_1 = {3d 5f 74 57 2c 74 35 3d } //01 00  =_tW,t5=
		$a_01_2 = {7d 6d 31 65 6a 5b 72 } //00 00  }m1ej[r
	condition:
		any of ($a_*)
 
}
rule Adware_MacOS_Pirrit_C_2{
	meta:
		description = "Adware:MacOS/Pirrit.C,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 72 6f 6a 65 63 74 73 2f 70 69 72 72 69 74 2f 6d 61 63 6f 73 2f 50 72 6f 78 79 53 65 72 76 65 72 } //01 00  projects/pirrit/macos/ProxyServer
		$a_00_1 = {74 68 65 63 6c 6f 75 64 73 65 72 76 69 63 65 73 2e 6e 65 74 } //01 00  thecloudservices.net
		$a_00_2 = {72 65 63 5f 73 63 72 69 70 74 2e 73 68 } //01 00  rec_script.sh
		$a_00_3 = {41 64 73 50 72 6f 78 79 45 6e 67 69 6e 65 3a 3a 69 6e 69 74 28 29 } //00 00  AdsProxyEngine::init()
		$a_00_4 = {5d 04 00 } //00 ef 
	condition:
		any of ($a_*)
 
}