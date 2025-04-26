
rule Trojan_Win32_Guloader_CCJC_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CCJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {65 75 72 6f 70 61 6b 6f 6e 74 6f 72 65 74 2e 47 61 6c } //1 europakontoret.Gal
		$a_01_1 = {53 6c 75 62 62 65 72 69 6e 67 2e 76 6f 63 } //1 Slubbering.voc
		$a_01_2 = {45 6d 6e 65 6f 6d 72 61 61 64 65 72 2e 62 65 62 } //1 Emneomraader.beb
		$a_01_3 = {47 65 6e 65 72 61 74 69 6f 6e 2e 74 78 74 } //1 Generation.txt
		$a_01_4 = {63 75 74 74 6c 65 66 69 73 68 2e 6b 69 63 } //1 cuttlefish.kic
		$a_01_5 = {73 6b 6f 73 76 72 74 65 6e 2e 64 6c 6c } //5 skosvrten.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*5) >=10
 
}