
rule Adware_Win32_SquareNet_I{
	meta:
		description = "Adware:Win32/SquareNet.I,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 00 64 00 74 00 6d 00 70 00 2e 00 64 00 61 00 74 00 } //01 00  ldtmp.dat
		$a_01_1 = {64 6f 77 6e 6c 6f 61 64 2e 64 61 74 } //00 00  download.dat
	condition:
		any of ($a_*)
 
}