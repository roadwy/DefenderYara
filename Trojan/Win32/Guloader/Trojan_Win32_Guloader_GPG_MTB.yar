
rule Trojan_Win32_Guloader_GPG_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_81_0 = {62 6f 67 66 65 72 6e } //1 bogfern
		$a_81_1 = {73 61 6c 61 74 64 72 65 73 73 69 6e 67 65 72 20 69 6e 74 65 72 72 65 61 63 74 20 6b 69 63 6b 61 } //1 salatdressinger interreact kicka
		$a_81_2 = {61 6c 6b 79 6e 65 73 20 64 65 6d 69 73 73 69 6f 6e 65 72 65 73 2e 65 78 65 } //1 alkynes demissioneres.exe
		$a_81_3 = {6d 65 64 76 69 64 65 6e 64 65 20 74 65 72 6d 69 6e 61 6c 66 61 63 69 6c 69 74 65 74 } //1 medvidende terminalfacilitet
		$a_81_4 = {66 6f 72 73 74 61 6e 64 65 72 69 6e 64 65 20 73 74 61 62 69 6c 65 } //1 forstanderinde stabile
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=4
 
}