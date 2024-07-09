
rule TrojanProxy_Win32_Bunitu_N{
	meta:
		description = "TrojanProxy:Win32/Bunitu.N,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {80 7f 10 33 75 20 33 c0 68 ?? ?? ?? ?? 50 ff 77 11 68 ?? ?? ?? ?? ff 04 24 } //1
		$a_03_1 = {b2 6e 86 d6 88 70 04 b2 65 86 d6 88 70 08 51 b9 ?? ?? ?? ?? 87 d1 29 10 59 } //1
		$a_01_2 = {83 c0 78 83 c0 78 c1 e8 0a 56 be 3c 00 00 00 3b c6 72 10 83 e8 1e 83 e8 1e 41 3b ce 75 03 } //1
		$a_03_3 = {4a 0b d2 75 11 0f 31 0f b6 c0 c1 e0 02 bf ?? ?? ?? ?? 03 f8 eb 05 83 3f 00 75 e5 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}