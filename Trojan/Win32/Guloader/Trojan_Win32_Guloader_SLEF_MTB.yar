
rule Trojan_Win32_Guloader_SLEF_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SLEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 00 75 00 72 00 74 00 6c 00 69 00 6e 00 67 00 6c 00 79 00 20 00 65 00 72 00 67 00 6f 00 6d 00 65 00 74 00 65 00 72 00 63 00 79 00 6b 00 6c 00 65 00 6e 00 2e 00 65 00 78 00 65 00 } //2 hurtlingly ergometercyklen.exe
		$a_01_1 = {70 00 6f 00 6c 00 79 00 70 00 68 00 61 00 73 00 61 00 6c 00 20 00 73 00 6e 00 6f 00 74 00 6e 00 73 00 65 00 74 00 } //2 polyphasal snotnset
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}