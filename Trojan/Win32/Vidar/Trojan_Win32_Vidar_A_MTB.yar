
rule Trojan_Win32_Vidar_A_MTB{
	meta:
		description = "Trojan:Win32/Vidar.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 00 43 00 4f 00 59 00 53 00 2f 00 2f 00 2f 00 68 00 64 00 72 00 } //1 CCOYS///hdr
		$a_01_1 = {77 00 61 00 6c 00 6c 00 65 00 74 00 2e 00 64 00 61 00 74 00 } //1 wallet.dat
		$a_01_2 = {6d 00 6f 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 } //1 mozzzzzzzzzzz
		$a_03_3 = {40 8a 0c 85 90 01 04 8b 45 08 32 0c 03 a1 90 01 04 88 0c 18 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}