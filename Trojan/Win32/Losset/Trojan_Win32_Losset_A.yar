
rule Trojan_Win32_Losset_A{
	meta:
		description = "Trojan:Win32/Losset.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {47 6c 6f 62 61 6c 5c 67 6f 6f 6c 20 25 64 } //1 Global\gool %d
		$a_02_1 = {57 69 6e 6c 6f 67 6f 6e 90 02 04 43 56 69 64 65 6f 43 61 70 90 00 } //1
		$a_00_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 Applications\iexplore.exe\shell\open\command
		$a_00_3 = {52 65 73 65 74 53 53 44 54 } //1 ResetSSDT
		$a_00_4 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}