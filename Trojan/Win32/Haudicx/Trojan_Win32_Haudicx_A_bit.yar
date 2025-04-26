
rule Trojan_Win32_Haudicx_A_bit{
	meta:
		description = "Trojan:Win32/Haudicx.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 2a 00 2e 00 64 00 6f 00 63 00 } //1 \*.doc
		$a_01_1 = {45 78 74 20 3d 20 64 6f 63 2c 70 64 66 } //1 Ext = doc,pdf
		$a_01_2 = {46 69 6c 65 43 6f 70 79 2c 20 25 41 5f 4c 6f 6f 70 46 69 6c 65 46 75 6c 6c 50 61 74 68 25 2c 20 25 43 54 46 25 5c 25 41 5f 4c 6f 6f 70 46 69 6c 65 4e 61 6d 65 25 } //1 FileCopy, %A_LoopFileFullPath%, %CTF%\%A_LoopFileName%
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}