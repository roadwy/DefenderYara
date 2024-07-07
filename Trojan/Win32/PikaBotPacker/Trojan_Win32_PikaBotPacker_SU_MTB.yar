
rule Trojan_Win32_PikaBotPacker_SU_MTB{
	meta:
		description = "Trojan:Win32/PikaBotPacker.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 1a 03 5d 90 01 01 2b d8 90 00 } //1
		$a_03_1 = {03 d8 8b 45 90 01 01 89 18 90 00 } //1
		$a_03_2 = {2b d8 8b 45 90 01 01 31 18 90 00 } //1
		$a_03_3 = {2b d8 01 5d 90 01 01 8b 45 90 01 01 3b 45 90 01 01 0f 82 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}