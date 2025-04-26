
rule Trojan_Win32_NSISInjector_EC_MTB{
	meta:
		description = "Trojan:Win32/NSISInjector.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 6b 61 74 74 65 64 65 70 61 72 74 65 6d 65 6e 74 65 74 5c 41 6e 61 67 6f 67 79 2e 64 6c 6c } //1 Skattedepartementet\Anagogy.dll
		$a_01_1 = {5c 44 61 69 74 79 61 2e 69 6e 69 } //1 \Daitya.ini
		$a_01_2 = {5c 47 6c 64 73 66 6f 72 64 72 69 6e 67 } //1 \Gldsfordring
		$a_01_3 = {41 4d 44 2e 50 6f 77 65 72 2e 50 72 6f 63 65 73 73 6f 72 2e 70 70 6b 67 } //1 AMD.Power.Processor.ppkg
		$a_01_4 = {5c 56 69 72 74 75 6f 73 61 5c 4c 69 76 6f 72 } //1 \Virtuosa\Livor
		$a_01_5 = {50 53 52 65 61 64 6c 69 6e 65 2e 70 73 64 31 } //1 PSReadline.psd1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}