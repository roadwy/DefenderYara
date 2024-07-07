
rule Trojan_Win32_NSISInject_SPXX_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.SPXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 65 6d 6f 70 68 69 6c 69 61 63 73 2e 74 78 74 } //1 hemophiliacs.txt
		$a_01_1 = {6d 6f 72 61 6c 6c 72 65 6e 2e 69 6e 69 } //1 morallren.ini
		$a_01_2 = {54 6f 76 62 61 6e 65 2e 69 6e 64 } //1 Tovbane.ind
		$a_01_3 = {68 79 65 74 6f 6d 65 74 65 72 2e 52 75 62 } //1 hyetometer.Rub
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}