
rule Trojan_BAT_Vidar_D_MTB{
	meta:
		description = "Trojan:BAT/Vidar.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {79 4b 61 52 47 2e 75 57 67 62 61 2e 72 65 73 6f 75 72 63 65 73 } //2 yKaRG.uWgba.resources
		$a_01_1 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //2 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
		$a_01_2 = {30 51 37 31 4a 31 4e 4f 4b 31 69 57 4f 46 65 47 65 74 2e 79 39 74 61 4a 51 5a 55 6d 34 77 39 69 37 51 46 36 71 } //2 0Q71J1NOK1iWOFeGet.y9taJQZUm4w9i7QF6q
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}