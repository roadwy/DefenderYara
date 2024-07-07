
rule Trojan_Win32_Emotet_PEB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f b6 44 34 90 01 01 0f b6 c9 03 c1 99 b9 90 01 04 f7 f9 8a 5c 14 90 01 01 32 5d 00 90 00 } //1
		$a_81_1 = {6f 50 47 6d 39 58 45 33 62 6f 4f 58 4a 44 71 4d 46 67 4f 4d 6d 41 41 59 53 52 4f 52 57 41 44 72 4e 7a 4f } //1 oPGm9XE3boOXJDqMFgOMmAAYSRORWADrNzO
		$a_81_2 = {58 69 61 75 54 66 6e 4f 41 63 6d 4b 6f 58 32 6c 66 36 4b 67 74 49 4c 63 6a 4f 6b 63 35 6a 76 45 58 } //1 XiauTfnOAcmKoX2lf6KgtILcjOkc5jvEX
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}