
rule Trojan_BAT_NjRat_NECJ_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NECJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {66 38 64 64 33 38 65 32 2d 66 30 33 66 2d 34 35 30 37 2d 61 39 34 36 2d 37 35 37 36 62 32 39 37 33 34 66 63 } //02 00  f8dd38e2-f03f-4507-a946-7576b29734fc
		$a_01_1 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 53 70 6c 61 73 68 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //02 00  aR3nbf8dQp2feLmk31.SplashForm.resources
		$a_01_2 = {45 00 7a 00 69 00 72 00 69 00 7a 00 27 00 73 00 20 00 22 00 2e 00 4e 00 45 00 54 00 20 00 52 00 65 00 61 00 63 00 74 00 6f 00 72 00 } //01 00  Eziriz's ".NET Reactor
		$a_01_3 = {52 50 46 3a 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 } //00 00  RPF:SmartAssembly
	condition:
		any of ($a_*)
 
}