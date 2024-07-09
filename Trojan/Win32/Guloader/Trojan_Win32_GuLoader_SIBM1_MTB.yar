
rule Trojan_Win32_GuLoader_SIBM1_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBM1!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {25 00 20 00 50 00 2e 00 49 00 2e 00 43 00 20 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 } //1 % P.I.C Program
		$a_00_1 = {5a 6f 75 61 76 65 35 } //1 Zouave5
		$a_03_2 = {b8 00 00 00 00 [0-0a] 50 [0-6a] b8 ?? ?? ?? ?? [0-f0] 01 c2 [0-6a] ff 12 [0-70] ff 37 [0-0a] 5d [0-6a] 31 f5 [0-0a] 31 2c 10 [0-6a] 83 c2 04 [0-0a] 83 c7 04 [0-6a] 81 fa ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? [0-6a] 50 [0-0a] c3 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}