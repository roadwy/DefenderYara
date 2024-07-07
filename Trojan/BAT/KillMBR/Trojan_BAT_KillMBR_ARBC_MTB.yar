
rule Trojan_BAT_KillMBR_ARBC_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.ARBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {79 6f 75 72 20 68 61 72 64 20 64 69 73 6b 20 68 61 73 20 62 65 65 6e 20 70 65 72 6d 61 6e 65 6e 74 6c 79 20 6c 6f 63 6b 65 64 2c 20 62 75 74 20 79 6f 75 20 63 61 6e 20 72 65 63 6f 76 65 72 20 69 74 } //2 your hard disk has been permanently locked, but you can recover it
		$a_01_1 = {73 65 6e 64 20 33 30 30 24 20 74 6f 20 74 68 69 73 20 61 64 64 72 65 73 73 } //2 send 300$ to this address
		$a_80_2 = {2f 63 20 73 68 75 74 64 6f 77 6e 20 2f 72 20 2f 66 20 2f 74 20 30 } ///c shutdown /r /f /t 0  2
		$a_80_3 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //\\.\PhysicalDrive0  2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=8
 
}