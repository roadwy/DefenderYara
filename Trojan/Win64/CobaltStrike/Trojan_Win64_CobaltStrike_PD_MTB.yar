
rule Trojan_Win64_CobaltStrike_PD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 30 32 64 2f 25 30 32 64 2f 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 } //01 00  %02d/%02d/%02d %02d:%02d:%02d
		$a_01_1 = {25 73 20 61 73 20 25 73 5c 25 73 3a 20 25 64 } //01 00  %s as %s\%s: %d
		$a_01_2 = {53 74 61 72 74 65 64 20 73 65 72 76 69 63 65 20 25 73 20 6f 6e 20 25 73 } //01 00  Started service %s on %s
		$a_01_3 = {62 65 61 63 6f 6e 2e 64 6c 6c } //01 00  beacon.dll
		$a_01_4 = {62 65 61 63 6f 6e 2e 78 36 34 2e 64 6c 6c } //01 00  beacon.x64.dll
		$a_01_5 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //01 00  ReflectiveLoader
		$a_01_6 = {25 73 20 28 61 64 6d 69 6e 29 } //01 00  %s (admin)
		$a_01_7 = {55 70 64 61 74 65 72 2e 64 6c 6c } //01 00  Updater.dll
		$a_01_8 = {4c 69 62 54 6f 6d 4d 61 74 68 } //01 00  LibTomMath
		$a_01_9 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6f 63 74 65 74 2d 73 74 72 65 61 6d } //01 00  Content-Type: application/octet-stream
		$a_01_10 = {72 69 6a 6e 64 61 65 6c } //01 00  rijndael
		$a_03_11 = {2e 2f 2e 2f 2e 2c 90 02 04 2e 2c 2e 2f 90 00 } //01 00 
		$a_03_12 = {69 68 69 68 69 6b 90 02 04 69 6b 69 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}