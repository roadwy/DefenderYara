
rule Trojan_Win32_Phosae_B_dha{
	meta:
		description = "Trojan:Win32/Phosae.B!dha,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 78 38 37 61 31 34 35 66 32 2c 20 30 78 39 30 34 34 2c 20 30 78 34 65 64 64 2c 20 30 78 62 39 2c 20 30 78 39 66 2c 20 30 78 63 30 2c 20 30 78 65 39 2c 20 30 78 32 31 2c 20 30 78 61 30 2c 20 30 78 66 38 2c 20 30 78 35 31 } //00 00 
	condition:
		any of ($a_*)
 
}