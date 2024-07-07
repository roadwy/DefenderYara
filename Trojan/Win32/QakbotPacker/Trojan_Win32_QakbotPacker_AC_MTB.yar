
rule Trojan_Win32_QakbotPacker_AC_MTB{
	meta:
		description = "Trojan:Win32/QakbotPacker.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 03 1d 90 01 04 43 90 02 30 03 d8 43 a1 90 01 04 33 18 89 1d 90 02 30 8b 1d 90 01 04 2b d8 90 02 30 2b d8 90 02 30 2b d8 a1 90 01 04 89 18 90 02 30 8b 1d 90 01 04 83 c3 04 2b d8 90 02 30 2b d8 89 1d 90 01 04 33 c0 a3 90 02 30 8b 1d 90 01 04 83 c3 04 03 1d 90 01 04 2b d8 90 02 30 2b d8 90 02 30 03 d8 89 1d 90 01 04 a1 90 01 04 3b 05 90 01 04 0f 82 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}