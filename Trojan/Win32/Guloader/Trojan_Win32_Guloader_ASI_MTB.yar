
rule Trojan_Win32_Guloader_ASI_MTB{
	meta:
		description = "Trojan:Win32/Guloader.ASI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {61 70 6f 74 65 6b 65 72 62 65 76 69 6c 6c 69 6e 67 73 2e 74 78 74 } //1 apotekerbevillings.txt
		$a_01_1 = {74 72 6e 69 6e 67 73 64 72 61 67 74 65 72 6e 65 73 5c 6d 69 73 64 61 6e 6e 65 73 5c 54 65 6b 73 74 69 6c 66 61 72 76 65 72 73 } //1 trningsdragternes\misdannes\Tekstilfarvers
		$a_01_2 = {74 79 76 65 72 69 73 69 6b 72 65 6e 64 65 73 2e 64 6c 6c } //1 tyverisikrendes.dll
		$a_01_3 = {55 6e 72 68 79 6d 65 64 2e 61 64 69 } //1 Unrhymed.adi
		$a_01_4 = {63 68 72 69 73 74 69 61 6e 73 68 61 76 6e 65 72 6e 65 2e 64 65 68 } //1 christianshavnerne.deh
		$a_01_5 = {73 74 6f 70 70 65 67 61 72 6e 73 2e 62 72 61 } //1 stoppegarns.bra
		$a_01_6 = {6e 6f 72 6d 61 6c 66 6f 72 64 65 6c 74 65 2e 6a 70 67 } //1 normalfordelte.jpg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}