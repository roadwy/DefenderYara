
rule Trojan_BAT_AsyncRat_AMMH_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AMMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 08 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 03 07 6f 90 01 01 00 00 0a 61 d1 0d 12 03 28 90 01 01 00 00 0a 13 04 06 11 04 6f 90 01 01 00 00 0a 26 07 03 6f 90 01 01 00 00 0a 17 59 3b 90 01 01 00 00 00 07 17 58 38 90 01 01 00 00 00 16 0b 08 18 58 0c 08 02 6f 90 01 01 00 00 0a 32 b0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AsyncRat_AMMH_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.AMMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {fe 0c 02 00 fe 0c 01 00 6f 90 01 01 00 00 0a 20 01 00 00 00 73 90 01 01 00 00 0a 25 fe 0c 00 00 20 90 01 01 00 00 00 fe 0c 00 00 8e 69 6f 90 01 01 00 00 0a 25 6f 90 01 01 00 00 0a fe 0c 02 00 6f 90 01 01 00 00 0a fe 0e 00 00 fe 0c 02 00 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 20 90 01 01 ff ff ff 28 90 01 01 00 00 0a fe 0e 03 00 90 00 } //01 00 
		$a_80_1 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //IsDebuggerPresent  01 00 
		$a_80_2 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //CheckRemoteDebuggerPresent  01 00 
		$a_80_3 = {67 65 74 5f 49 73 41 74 74 61 63 68 65 64 } //get_IsAttached  00 00 
	condition:
		any of ($a_*)
 
}