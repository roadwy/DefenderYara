
rule Trojan_Win32_Guloader_KAB_MTB{
	meta:
		description = "Trojan:Win32/Guloader.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 6f 6c 6c 75 67 69 6e 61 63 65 61 65 } //1 molluginaceae
		$a_01_1 = {6c 69 74 68 61 73 } //1 lithas
		$a_01_2 = {6e 69 6b 6b 65 6e 64 65 } //1 nikkende
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}