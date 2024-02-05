
rule Trojan_BAT_CryptInject_PE_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 30 36 41 35 36 35 32 34 2d 34 46 46 33 2d 34 34 45 30 2d 39 45 45 44 2d 34 39 31 38 33 37 37 33 35 42 36 38 } //01 00 
		$a_01_1 = {73 61 64 77 71 65 35 34 71 77 65 35 77 71 37 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_01_2 = {31 32 33 31 2e 31 32 33 31 32 2e 31 2e 31 } //00 00 
	condition:
		any of ($a_*)
 
}