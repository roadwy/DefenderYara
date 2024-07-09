
rule Trojan_Win32_PikaBotPacker_SU_MTB{
	meta:
		description = "Trojan:Win32/PikaBotPacker.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 1a 03 5d ?? 2b d8 } //1
		$a_03_1 = {03 d8 8b 45 ?? 89 18 } //1
		$a_03_2 = {2b d8 8b 45 ?? 31 18 } //1
		$a_03_3 = {2b d8 01 5d ?? 8b 45 ?? 3b 45 ?? 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}