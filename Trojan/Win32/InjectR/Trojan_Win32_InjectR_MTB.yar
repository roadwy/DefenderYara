
rule Trojan_Win32_InjectR_MTB{
	meta:
		description = "Trojan:Win32/InjectR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 46 00 75 00 63 00 6b 00 20 00 59 00 6f 00 75 00 20 00 4e 00 4f 00 44 00 2c 00 20 00 41 00 56 00 41 00 53 00 54 00 20 00 61 00 6e 00 64 00 20 00 61 00 6c 00 6c 00 20 00 41 00 56 00 73 } //00 00 
	condition:
		any of ($a_*)
 
}