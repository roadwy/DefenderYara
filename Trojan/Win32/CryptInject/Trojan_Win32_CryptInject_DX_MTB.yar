
rule Trojan_Win32_CryptInject_DX_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 45 58 63 58 56 2e 64 6c 6c } //01 00  fEXcXV.dll
		$a_01_1 = {79 77 75 4d 4c 6a 42 76 2e 64 6c 6c } //01 00  ywuMLjBv.dll
		$a_01_2 = {42 49 69 74 64 41 64 42 6b 42 2e 64 6c 6c } //01 00  BIitdAdBkB.dll
		$a_01_3 = {6d 58 78 52 49 71 4e 51 7a 6a 2e 64 6c 6c } //01 00  mXxRIqNQzj.dll
		$a_01_4 = {6d 55 45 6b 64 50 4a 59 2e 64 6c 6c } //00 00  mUEkdPJY.dll
	condition:
		any of ($a_*)
 
}