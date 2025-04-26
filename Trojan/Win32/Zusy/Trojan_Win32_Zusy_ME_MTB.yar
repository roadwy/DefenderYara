
rule Trojan_Win32_Zusy_ME_MTB{
	meta:
		description = "Trojan:Win32/Zusy.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 52 43 59 54 56 55 42 49 2e 44 4c 4c } //10 TRCYTVUBI.DLL
		$a_01_1 = {52 74 79 76 67 62 4b 62 68 } //1 RtyvgbKbh
		$a_01_2 = {4b 6e 6a 69 68 62 45 66 74 76 67 } //1 KnjihbEftvg
		$a_01_3 = {4c 62 68 67 76 4f 6a 68 62 67 } //1 LbhgvOjhbg
		$a_01_4 = {47 65 74 43 75 72 72 65 6e 74 54 68 72 65 61 64 49 64 } //1 GetCurrentThreadId
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}