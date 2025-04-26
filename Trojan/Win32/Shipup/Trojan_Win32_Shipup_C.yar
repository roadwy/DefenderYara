
rule Trojan_Win32_Shipup_C{
	meta:
		description = "Trojan:Win32/Shipup.C,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 04 8a 08 84 c9 74 08 80 e9 02 88 08 40 eb } //10
		$a_01_1 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 autorun.inf
		$a_01_2 = {4d 69 63 72 6f 73 6f 66 74 53 68 69 70 } //1 MicrosoftShip
		$a_01_3 = {4e 6f 44 72 69 76 65 54 79 70 65 41 75 74 6f 52 75 6e } //1 NoDriveTypeAutoRun
		$a_01_4 = {4d 61 79 62 65 20 61 20 45 6e 63 72 79 70 74 65 64 20 46 6c 61 73 68 20 44 69 73 6b } //1 Maybe a Encrypted Flash Disk
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}