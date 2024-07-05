
rule Trojan_BAT_AmsiBypass_CCHZ_MTB{
	meta:
		description = "Trojan:BAT/AmsiBypass.CCHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 07 00 00 0a 00 "
		
	strings :
		$a_81_0 = {61 6d 73 69 2e 64 6c 6c } //0a 00  amsi.dll
		$a_81_1 = {41 6d 73 69 53 63 61 6e 42 75 66 66 65 72 } //0a 00  AmsiScanBuffer
		$a_81_2 = {59 57 31 7a 61 53 35 6b 62 47 77 3d } //0a 00  YW1zaS5kbGw=
		$a_81_3 = {51 57 31 7a 61 56 4e 6a 59 57 35 43 64 57 5a 6d 5a 58 49 3d } //01 00  QW1zaVNjYW5CdWZmZXI=
		$a_01_4 = {44 38 34 46 34 43 31 32 30 30 30 35 46 31 38 33 37 44 43 36 35 43 30 34 31 38 31 46 33 44 41 39 34 36 36 42 31 32 33 46 43 33 36 39 43 33 35 39 41 33 30 31 42 41 42 43 31 32 30 36 31 35 37 30 } //01 00  D84F4C120005F1837DC65C04181F3DA9466B123FC369C359A301BABC12061570
		$a_81_5 = {50 61 74 63 68 20 41 70 70 6c 69 65 64 } //01 00  Patch Applied
		$a_81_6 = {54 68 65 20 6e 75 6d 62 65 72 20 6f 66 20 70 72 6f 63 65 73 73 65 73 20 69 6e 20 74 68 65 20 73 79 73 74 65 6d 20 69 73 20 6c 65 73 73 20 74 68 61 6e 20 34 30 2e 20 45 78 69 74 69 6e 67 20 74 68 65 20 70 72 6f 67 72 61 6d } //00 00  The number of processes in the system is less than 40. Exiting the program
	condition:
		any of ($a_*)
 
}