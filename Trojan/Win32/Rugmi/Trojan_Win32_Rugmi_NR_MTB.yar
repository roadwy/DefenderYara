
rule Trojan_Win32_Rugmi_NR_MTB{
	meta:
		description = "Trojan:Win32/Rugmi.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4c d6 08 03 c8 89 4c d5 90 01 01 8b 4c d6 0c 03 c8 89 4c d5 90 01 01 42 81 fa ff 0b 00 00 72 e3 90 00 } //3
		$a_03_1 = {e9 e3 fe ff ff 8d b6 00 00 00 00 0c 90 01 01 75 08 e8 7b 00 00 00 8b c8 e8 d4 ea ff ff 8b 45 08 5d 90 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}