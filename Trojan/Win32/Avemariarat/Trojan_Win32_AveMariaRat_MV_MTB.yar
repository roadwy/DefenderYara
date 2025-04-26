
rule Trojan_Win32_AveMariaRat_MV_MTB{
	meta:
		description = "Trojan:Win32/AveMariaRat.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0c 8a 0c 0a 88 4c 05 08 ?? 01 00 00 00 c1 ?? 00 ?? 01 00 00 00 c1 ?? 00 8b ?? 0c 8a 14 11 88 54 05 08 ?? 01 00 00 00 d1 [0-05] b9 01 00 00 00 d1 ?? 8b ?? 0c 8a 04 02 88 44 0d 08 ?? 01 00 00 00 6b ?? 03 ?? 01 00 00 00 6b ?? 03 8b ?? 0c 8a 14 10 88 54 0d 08 } //1
		$a_01_1 = {43 72 65 61 74 65 54 68 72 65 61 64 } //1 CreateThread
		$a_01_2 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //1 LockResource
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}