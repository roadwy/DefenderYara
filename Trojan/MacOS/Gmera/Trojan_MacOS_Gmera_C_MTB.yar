
rule Trojan_MacOS_Gmera_C_MTB{
	meta:
		description = "Trojan:MacOS/Gmera.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 6f 69 6e 74 72 61 7a 65 72 } //01 00  Cointrazer
		$a_00_1 = {6e 61 67 73 72 73 64 66 73 75 64 69 6e 61 73 61 2e 63 6f 6d 2f 6c 69 6e 6b 2e 70 68 70 } //01 00  nagsrsdfsudinasa.com/link.php
		$a_00_2 = {63 6f 6d 2e 61 70 70 49 65 2e 54 72 65 7a 61 72 75 73 69 6f 73 2e 54 72 65 7a 61 72 75 73 } //01 00  com.appIe.Trezarusios.Trezarus
		$a_00_3 = {41 32 36 35 48 53 42 39 32 46 } //00 00  A265HSB92F
	condition:
		any of ($a_*)
 
}