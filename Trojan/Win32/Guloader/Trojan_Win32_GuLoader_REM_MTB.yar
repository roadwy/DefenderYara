
rule Trojan_Win32_GuLoader_REM_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.REM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {67 6f 79 61 7a 69 74 65 20 61 62 6f 72 74 6d 6f 64 73 74 61 6e 64 65 72 65 20 61 6e 64 65 6c 73 76 69 72 6b 73 6f 6d 68 65 64 65 6e } //1 goyazite abortmodstandere andelsvirksomheden
		$a_81_1 = {63 6f 75 67 61 72 20 74 6f 72 73 6b 65 66 69 73 6b 65 72 69 65 72 73 20 61 6b 75 70 75 6e 6b 74 72 65 6e } //1 cougar torskefiskeriers akupunktren
		$a_81_2 = {62 69 66 69 67 75 72 65 6e } //1 bifiguren
		$a_81_3 = {75 6e 64 73 65 65 6c 69 67 73 74 65 73 } //1 undseeligstes
		$a_81_4 = {61 66 68 6f 70 70 65 72 65 6e 73 20 6f 63 63 61 6d 69 74 65 2e 65 78 65 } //1 afhopperens occamite.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}