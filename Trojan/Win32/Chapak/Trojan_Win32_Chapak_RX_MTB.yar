
rule Trojan_Win32_Chapak_RX_MTB{
	meta:
		description = "Trojan:Win32/Chapak.RX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 74 72 65 74 63 68 5c 31 31 37 5c 70 61 73 74 5c 64 72 65 61 6d 2e 70 64 62 } //1 Stretch\117\past\dream.pdb
		$a_01_1 = {64 72 65 61 6d 2e 64 6c 6c } //1 dream.dll
		$a_01_2 = {43 61 6d 70 61 72 72 69 76 65 } //1 Camparrive
		$a_01_3 = {48 69 73 74 6f 72 79 6c 69 67 68 74 } //1 Historylight
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}