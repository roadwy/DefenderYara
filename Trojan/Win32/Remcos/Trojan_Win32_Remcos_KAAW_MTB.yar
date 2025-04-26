
rule Trojan_Win32_Remcos_KAAW_MTB{
	meta:
		description = "Trojan:Win32/Remcos.KAAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {64 6f 62 62 65 6c 74 65 6b 73 70 6f 6e 65 72 69 6e 67 65 72 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 68 6f 72 69 7a 6f 6e 74 69 63 61 6c 5c 55 6e 69 6e 73 74 61 6c 6c 5c 73 70 61 6c 74 65 74 65 6b 73 74 65 72 6e 65 73 } //dobbelteksponeringer\Microsoft\Windows\horizontical\Uninstall\spalteteksternes  1
		$a_80_1 = {76 61 6e 64 72 65 72 6b 6f 72 74 65 74 5c 41 6e 67 72 65 62 73 74 69 64 73 70 75 6e 6b 74 65 74 5c 69 6e 64 6f 6e 65 73 69 65 6e 73 } //vandrerkortet\Angrebstidspunktet\indonesiens  1
		$a_80_2 = {75 6e 73 70 65 64 5c 61 6b 6b 6f 72 64 65 72 69 6e 67 65 72 6e 65 73 } //unsped\akkorderingernes  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}