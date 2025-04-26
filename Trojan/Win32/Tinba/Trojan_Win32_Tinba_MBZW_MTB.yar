
rule Trojan_Win32_Tinba_MBZW_MTB{
	meta:
		description = "Trojan:Win32/Tinba.MBZW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c4 28 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 e0 25 40 00 80 24 40 00 cc 14 40 00 78 00 00 00 82 00 00 00 8c } //1
		$a_01_1 = {4f 6c 79 6d 70 69 63 53 74 00 44 65 61 6c 61 68 6f 79 61 00 00 44 65 61 6c 61 68 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}