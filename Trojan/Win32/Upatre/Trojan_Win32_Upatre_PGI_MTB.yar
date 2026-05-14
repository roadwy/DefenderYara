
rule Trojan_Win32_Upatre_PGI_MTB{
	meta:
		description = "Trojan:Win32/Upatre.PGI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 39 2c 43 37 2c 32 45 2c 39 46 2c 42 46 2c 36 43 2c 41 41 2c 34 36 2c 37 36 2c 36 38 2c 31 36 2c 30 32 2c 43 44 2c 30 42 2c 38 37 2c 32 45 2c 41 35 2c 43 39 2c 45 34 2c 46 31 2c 41 39 2c 44 36 2c 34 45 2c 43 37 2c 36 43 2c 39 44 2c 45 34 2c 41 36 2c 35 39 2c 32 33 2c 30 46 2c 37 31 2c 33 33 } //20 A9,C7,2E,9F,BF,6C,AA,46,76,68,16,02,CD,0B,87,2E,A5,C9,E4,F1,A9,D6,4E,C7,6C,9D,E4,A6,59,23,0F,71,33
	condition:
		((#a_01_0  & 1)*20) >=20
 
}