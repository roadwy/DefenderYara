
rule TrojanProxy_Win32_Pramro_B{
	meta:
		description = "TrojanProxy:Win32/Pramro.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f be 85 d4 ef ff ff 83 f8 47 75 18 0f be 8d d5 ef ff ff 83 f9 45 75 0c 90 09 05 00 e9 90 01 01 04 00 00 90 00 } //1
		$a_03_1 = {8a 84 15 f4 eb ff ff 34 90 01 01 8b 8d ec db ff ff 88 84 0d f4 eb ff ff eb c5 90 00 } //1
		$a_01_2 = {68 6f 73 74 61 2e 65 78 65 00 73 74 72 63 73 70 6e 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}