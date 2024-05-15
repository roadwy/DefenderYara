
rule Trojan_BAT_Rhadamanthys_MBZU_MTB{
	meta:
		description = "Trojan:BAT/Rhadamanthys.MBZU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 73 69 73 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e 00 43 6f 72 72 65 63 74 00 4d 53 47 5f 4e 45 54 00 4f 62 6a 65 63 74 00 50 72 6f 67 72 61 6d 00 41 6e 67 65 6c 6f 00 44 67 61 73 79 75 64 67 75 79 67 69 75 78 48 49 41 00 4d 75 6c 74 69 63 61 } //00 00 
	condition:
		any of ($a_*)
 
}