
rule Trojan_Win32_AsyncRat_PA_MTB{
	meta:
		description = "Trojan:Win32/AsyncRat.PA!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5a 00 33 00 4a 00 68 00 59 00 6d 00 4a 00 6c 00 63 00 6c 00 39 00 7a 00 62 00 6d 00 46 00 77 00 63 00 32 00 68 00 76 00 64 00 41 00 } //01 00 
		$a_01_1 = {59 00 6d 00 39 00 30 00 53 00 32 00 6c 00 73 00 62 00 47 00 56 00 79 00 } //01 00 
		$a_01_2 = {61 00 32 00 56 00 35 00 54 00 47 00 39 00 6e 00 5a 00 32 00 56 00 79 00 } //00 00 
	condition:
		any of ($a_*)
 
}