
rule Trojan_BAT_AsyncRat_SGF_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.SGF!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 75 6e 48 69 64 64 65 6e 43 6f 6d 6d 61 6e 64 } //01 00  RunHiddenCommand
		$a_01_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //01 00  powershell.exe
		$a_01_2 = {52 61 77 41 63 63 65 6c 2e 65 78 65 } //00 00  RawAccel.exe
	condition:
		any of ($a_*)
 
}