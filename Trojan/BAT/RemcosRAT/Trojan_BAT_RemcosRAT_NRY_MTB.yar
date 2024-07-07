
rule Trojan_BAT_RemcosRAT_NRY_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.NRY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {28 1a 00 00 0a 1a 2d 09 26 06 39 90 01 01 00 00 00 2b 03 0a 2b f5 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 17 2d 0c 26 06 6f 90 01 01 00 00 0a 17 90 00 } //5
		$a_01_1 = {4e 00 75 00 66 00 6b 00 61 00 64 00 6f 00 6b 00 66 00 72 00 78 00 78 00 79 00 71 00 66 00 73 00 76 00 64 00 7a 00 6b 00 62 00 68 00 7a 00 2e 00 55 00 66 00 6b 00 6b 00 68 00 7a 00 6a 00 6b 00 74 00 69 00 67 00 73 00 6c 00 6e 00 71 00 7a 00 73 00 74 00 70 00 71 00 70 00 } //1 Nufkadokfrxxyqfsvdzkbhz.Ufkkhzjktigslnqzstpqp
		$a_01_2 = {4b 00 44 00 45 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 73 00 } //1 KDE Softwares
		$a_01_3 = {43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 53 00 65 00 6e 00 74 00 69 00 6e 00 65 00 6c 00 } //1 Computer Sentinel
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}