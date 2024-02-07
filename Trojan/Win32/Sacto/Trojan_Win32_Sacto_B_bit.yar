
rule Trojan_Win32_Sacto_B_bit{
	meta:
		description = "Trojan:Win32/Sacto.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 00 20 00 20 00 20 00 2e 00 65 00 78 00 65 00 } //01 00      .exe
		$a_01_1 = {55 00 2d 00 53 00 65 00 72 00 69 00 61 00 6c 00 4e 00 75 00 6d 00 62 00 65 00 72 00 3a 00 20 00 25 00 58 00 2d 00 25 00 58 00 } //01 00  U-SerialNumber: %X-%X
		$a_01_2 = {6f 00 6e 00 66 00 69 00 67 00 2e 00 74 00 6d 00 70 00 } //01 00  onfig.tmp
		$a_01_3 = {5c 00 4d 00 53 00 4e 00 2e 00 6c 00 6e 00 6b 00 } //00 00  \MSN.lnk
	condition:
		any of ($a_*)
 
}