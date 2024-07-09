
rule Trojan_Win32_Emotet_PED_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 44 34 ?? 0f b6 c9 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 4d 00 8a 5c 14 ?? 32 d9 } //1
		$a_81_1 = {59 6f 4f 39 71 34 75 58 5a 4f 56 44 59 7a 30 59 73 31 51 4b 4b 58 52 54 77 65 38 54 71 42 50 6f 46 4f 44 6c 46 49 69 } //1 YoO9q4uXZOVDYz0Ys1QKKXRTwe8TqBPoFODlFIi
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}