
rule Trojan_Win32_Guloader_SLJH_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SLJH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 00 73 00 75 00 67 00 61 00 72 00 68 00 6f 00 75 00 73 00 65 00 73 00 5c 00 72 00 68 00 6f 00 6d 00 62 00 6f 00 69 00 64 00 65 00 73 00 2e 00 6c 00 6e 00 6b 00 } //2 \sugarhouses\rhomboides.lnk
		$a_01_1 = {53 00 74 00 61 00 6e 00 64 00 61 00 72 00 64 00 70 00 72 00 6f 00 64 00 75 00 6b 00 74 00 65 00 72 00 5c 00 74 00 65 00 6c 00 65 00 67 00 72 00 61 00 6d 00 6d 00 65 00 } //2 Standardprodukter\telegramme
		$a_01_2 = {5c 00 47 00 72 00 61 00 6d 00 6d 00 6f 00 66 00 6f 00 6e 00 70 00 6c 00 61 00 64 00 65 00 6e 00 37 00 2e 00 68 00 74 00 6d 00 22 00 } //2 \Grammofonpladen7.htm"
		$a_01_3 = {70 00 65 00 72 00 69 00 63 00 75 00 6c 00 6f 00 75 00 73 00 5c 00 54 00 72 00 61 00 6e 00 73 00 6c 00 65 00 74 00 74 00 65 00 72 00 } //2 periculous\Transletter
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}