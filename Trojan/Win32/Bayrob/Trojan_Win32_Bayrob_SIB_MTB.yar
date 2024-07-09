
rule Trojan_Win32_Bayrob_SIB_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 c1 89 da ?? [0-60] 89 11 83 c1 04 [0-30] 83 ea ?? [0-0a] 75 } //1
		$a_03_1 = {31 db e9 e3 [0-30] 8b 8a ?? ?? ?? ?? [0-10] 33 1c 8f [0-a0] 83 c2 04 [0-0a] 39 d0 [0-0a] 0f 84 ?? ?? ?? ?? [0-50] e9 } //1
		$a_03_2 = {89 74 24 04 89 3c 24 [0-30] e8 ?? ?? ?? ?? [0-30] 89 3c 24 [0-0a] e8 ?? ?? ?? ?? [0-40] 33 1d 69 76 43 00 [0-aa] b8 20 51 43 00 29 d8 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}