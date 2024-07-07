
rule Trojan_Win32_RedLine_RDEC_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 4a 47 68 79 75 78 47 41 55 49 73 61 69 75 6c 64 } //1 KJGhyuxGAUIsaiuld
		$a_01_1 = {78 62 79 75 69 64 67 41 59 55 37 75 69 6b 6a } //1 xbyuidgAYU7uikj
		$a_01_2 = {41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00 } //1 AppLaunch.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}