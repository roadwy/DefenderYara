
rule Trojan_Win32_LummaStealerClick_H{
	meta:
		description = "Trojan:Win32/LummaStealerClick.H,SIGNATURE_TYPE_CMDHSTR_EXT,32 00 32 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //10 powershell
		$a_00_1 = {6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } //10 net.webclient
		$a_00_2 = {5b 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 72 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 61 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 5d 00 3a 00 3a 00 6c 00 6f 00 61 00 64 00 28 00 24 00 } //10 [system.reflection.assembly]::load($
		$a_00_3 = {2e 00 69 00 6e 00 76 00 6f 00 6b 00 65 00 28 00 24 00 } //10 .invoke($
		$a_00_4 = {2e 00 68 00 65 00 61 00 64 00 65 00 72 00 73 00 2e 00 61 00 64 00 64 00 28 00 24 00 } //10 .headers.add($
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10) >=50
 
}