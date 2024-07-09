
rule Trojan_Win32_Zenpak_ASF_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 16 8b 35 [0-04] 8b 7d e4 0f b6 34 37 31 f2 88 d3 8b 55 dc 8b 75 e8 88 1c 16 eb } //1
		$a_01_1 = {4c 6e 6c 74 65 65 68 4f 73 74 65 72 62 70 } //1 LnlteehOsterbp
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}