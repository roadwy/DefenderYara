
rule Trojan_Win32_QHosts_U{
	meta:
		description = "Trojan:Win32/QHosts.U,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 07 00 00 "
		
	strings :
		$a_02_0 = {2f 63 6d 2e 70 68 70 3f 69 64 3d [0-04] 26 68 61 73 68 3d } //2
		$a_02_1 = {31 32 37 2e 30 2e 30 2e 31 [0-10] 6c 6f 63 61 6c 68 6f 73 74 } //2
		$a_00_2 = {64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //2 drivers\etc\hosts
		$a_00_3 = {63 6f 72 70 6f 72 61 74 65 66 61 63 74 6f 72 69 65 73 2e 63 6f 6d } //1 corporatefactories.com
		$a_00_4 = {56 69 72 75 73 42 6c 6f 6b 41 64 61 } //1 VirusBlokAda
		$a_00_5 = {6d 73 2e 6b 61 73 70 65 72 73 6b 79 2e 63 6f 6d } //1 ms.kaspersky.com
		$a_00_6 = {73 6b 79 70 65 64 65 61 6c 73 2e 63 6f 6d } //1 skypedeals.com
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=8
 
}