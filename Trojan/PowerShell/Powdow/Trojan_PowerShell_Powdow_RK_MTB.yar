
rule Trojan_PowerShell_Powdow_RK_MTB{
	meta:
		description = "Trojan:PowerShell/Powdow.RK!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 00 6f 00 77 00 65 00 72 00 53 00 68 00 65 00 6c 00 6c 00 } //1 PowerShell
		$a_00_1 = {2d 00 45 00 6e 00 63 00 6f 00 64 00 65 00 64 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //1 -EncodedCommand
		$a_00_2 = {2d 00 77 00 20 00 68 00 20 00 2d 00 65 00 } //1 -w h -e
		$a_00_3 = {61 00 51 00 42 00 6c 00 41 00 48 00 67 00 41 00 4b 00 41 00 42 00 70 00 41 00 48 00 63 00 41 00 63 00 67 00 41 00 67 00 41 00 43 00 30 00 41 00 56 00 51 00 42 00 79 00 41 00 47 00 6b 00 41 00 49 00 41 00 41 00 6e 00 41 00 47 00 67 00 41 00 64 00 41 00 42 00 30 00 41 00 48 00 41 00 41 00 } //10 aQBlAHgAKABpAHcAcgAgAC0AVQByAGkAIAAnAGgAdAB0AHAA
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*10) >=12
 
}