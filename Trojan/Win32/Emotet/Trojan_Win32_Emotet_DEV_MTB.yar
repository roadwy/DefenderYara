
rule Trojan_Win32_Emotet_DEV_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DEV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 ca 0c 00 00 f7 f9 8b 4c 24 18 8b ac 24 90 01 04 8a 04 29 8a 54 14 20 32 c2 88 04 29 90 00 } //1
		$a_81_1 = {4e 7a 4b 79 66 33 4e 79 48 57 6c 65 77 43 56 58 53 6f 70 4c 33 6d 53 50 4a 43 34 51 5a 4e 76 33 4a 73 44 57 } //1 NzKyf3NyHWlewCVXSopL3mSPJC4QZNv3JsDW
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}