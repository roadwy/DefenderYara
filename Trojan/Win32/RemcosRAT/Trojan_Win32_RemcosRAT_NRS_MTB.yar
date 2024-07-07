
rule Trojan_Win32_RemcosRAT_NRS_MTB{
	meta:
		description = "Trojan:Win32/RemcosRAT.NRS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {e8 c0 87 ff ff 0f b6 75 90 01 01 8b 45 f8 8a 4d 90 01 01 84 4c 30 19 75 1b 33 d2 39 55 10 74 0e 8b 45 f4 8b 00 0f b7 04 70 90 00 } //5
		$a_01_1 = {25 68 6f 6d 65 64 72 69 76 65 25 5c 65 65 67 76 } //1 %homedrive%\eegv
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}