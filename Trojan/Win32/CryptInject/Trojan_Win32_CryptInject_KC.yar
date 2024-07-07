
rule Trojan_Win32_CryptInject_KC{
	meta:
		description = "Trojan:Win32/CryptInject.KC,SIGNATURE_TYPE_PEHSTR,06 00 06 00 08 00 00 "
		
	strings :
		$a_01_0 = {46 75 72 6b 20 4b 65 79 53 79 73 74 65 6d } //1 Furk KeySystem
		$a_01_1 = {46 75 72 6b 4f 53 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 FurkOS.Properties.Resources
		$a_01_2 = {44 3a 5c 59 54 20 73 74 75 66 66 5c 53 6f 75 72 63 65 73 5c 46 75 72 6b 4f 53 5c 46 75 72 6b 4f 53 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 46 75 72 6b 4f 53 2e 70 64 62 } //1 D:\YT stuff\Sources\FurkOS\FurkOS\obj\Release\FurkOS.pdb
		$a_01_3 = {44 3a 5c 59 54 20 73 74 75 66 66 5c 46 75 72 6b 4f 53 5c 46 75 72 6b 4f 53 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 46 75 72 6b 4f 53 2e 70 64 62 } //1 D:\YT stuff\FurkOS\FurkOS\obj\Release\FurkOS.pdb
		$a_01_4 = {46 75 72 6b 4f 53 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 FurkOS.Form1.resources
		$a_01_5 = {46 75 72 6b 4f 53 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 FurkOS.Properties.Resources.resources
		$a_01_6 = {46 75 72 6b 4f 53 2e 6b 73 2e 72 65 73 6f 75 72 63 65 73 } //1 FurkOS.ks.resources
		$a_01_7 = {66 75 72 6b 54 61 62 73 } //1 furkTabs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=6
 
}