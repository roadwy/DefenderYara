
rule Trojan_Win32_Emotet_DEL_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c1 8b ce 99 f7 f9 8b 45 14 83 4d fc ff 8a 8c 15 ?? ?? ?? ?? 30 08 } //1
		$a_81_1 = {32 71 36 77 63 6d 30 67 31 6f 6d 33 6c 45 4d 53 68 79 4a 38 6d 43 7a 4d 70 4d 66 57 6a 64 38 42 } //1 2q6wcm0g1om3lEMShyJ8mCzMpMfWjd8B
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}