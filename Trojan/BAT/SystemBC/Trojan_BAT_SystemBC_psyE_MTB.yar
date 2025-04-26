
rule Trojan_BAT_SystemBC_psyE_MTB{
	meta:
		description = "Trojan:BAT/SystemBC.psyE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {d4 73 23 cd c7 f7 e2 fc ed 7e d9 d2 64 e3 18 b5 1a a7 3f 8a bf a6 75 e0 2c 3a 29 28 df 78 52 65 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}