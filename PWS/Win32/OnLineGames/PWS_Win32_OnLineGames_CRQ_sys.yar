
rule PWS_Win32_OnLineGames_CRQ_sys{
	meta:
		description = "PWS:Win32/OnLineGames.CRQ!sys,SIGNATURE_TYPE_PEHSTR,08 00 08 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {47 61 6d 65 48 61 63 6b 5c 52 65 67 44 72 69 76 65 72 5c 6f 62 6a 66 72 65 5c 69 33 38 36 5c 52 65 67 2e 70 64 62 } //02 00  GameHack\RegDriver\objfre\i386\Reg.pdb
		$a_01_1 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 63 00 3a 00 5c 00 6e 00 61 00 6d 00 65 00 2e 00 6c 00 6f 00 67 00 } //02 00  \DosDevices\c:\name.log
		$a_01_2 = {67 6e 61 69 78 6e 61 75 68 71 71 2e 64 6c 6c } //02 00  gnaixnauhqq.dll
		$a_01_3 = {6e 69 6c 75 77 2e 64 6c 6c } //02 00  niluw.dll
		$a_01_4 = {6e 61 69 78 75 68 7a 2e 64 6c 6c } //00 00  naixuhz.dll
	condition:
		any of ($a_*)
 
}