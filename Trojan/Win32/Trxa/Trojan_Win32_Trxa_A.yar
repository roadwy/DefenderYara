
rule Trojan_Win32_Trxa_A{
	meta:
		description = "Trojan:Win32/Trxa.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 0b 00 00 0a 00 "
		
	strings :
		$a_01_0 = {25 00 73 00 5c 00 25 00 64 00 5f 00 41 00 54 00 52 00 41 00 58 00 5f 00 42 00 4f 00 54 00 5f 00 25 00 64 00 } //02 00  %s\%d_ATRAX_BOT_%d
		$a_01_1 = {2e 6f 6e 69 6f 6e } //01 00  .onion
		$a_01_2 = {2f 61 75 74 68 2e 70 68 70 3f 61 3d } //01 00  /auth.php?a=
		$a_01_3 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 53 00 76 00 63 00 68 00 6f 00 73 00 74 00 } //01 00  Microsoft Svchost
		$a_01_4 = {64 6c 72 75 6e 6d 65 6d } //01 00  dlrunmem
		$a_01_5 = {64 6c 74 6f 72 65 78 65 63 } //01 00  dltorexec
		$a_01_6 = {64 6c 74 6f 72 72 75 6e 6d 65 6d } //01 00  dltorrunmem
		$a_01_7 = {69 6e 73 74 61 6c 6c 65 78 65 63 } //01 00  installexec
		$a_01_8 = {69 6e 73 74 61 6c 6c 61 74 69 6f 6e 6c 69 73 74 } //01 00  installationlist
		$a_01_9 = {73 74 61 72 74 62 74 63 } //01 00  startbtc
		$a_01_10 = {66 83 78 fc 2e 75 28 66 83 78 fe 45 74 07 66 83 78 fe 65 75 1a 66 83 38 58 74 06 66 83 38 78 75 0e 66 83 78 02 45 74 13 66 83 78 02 65 } //00 00 
	condition:
		any of ($a_*)
 
}