
rule Trojan_Win32_Tinba_MTV_MTB{
	meta:
		description = "Trojan:Win32/Tinba.MTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 11 88 55 d6 8b 4d f0 03 4d be 89 4d f0 8b 4d f4 03 4d be 89 4d f4 0f b6 4d d6 0f b6 55 d7 c7 45 ?? fb 9e f1 81 33 ca 8b 45 c6 88 08 c7 45 ?? 19 d9 b2 12 e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}