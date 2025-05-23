
rule Trojan_Win32_RiseProStealer_RHA_MTB{
	meta:
		description = "Trojan:Win32/RiseProStealer.RHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {0b 01 0e 22 00 ac 10 00 00 3e 04 00 00 00 00 00 00 c0 15 00 00 10 00 00 00 c0 10 } //2
		$a_03_1 = {2e 72 73 72 63 00 00 00 f8 0e 01 00 00 b0 14 00 f8 0e 01 00 00 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 00 00 00 00 00 00 00 00 00 80 01 00 00 c0 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 40 00 00 e0 } //2
		$a_01_2 = {e8 18 00 00 00 eb 03 } //2
		$a_02_3 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 ?? ?? ?? ?? 41 00 75 00 33 00 } //1
		$a_02_4 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 ?? ?? ?? ?? 41 00 79 00 33 00 49 00 6e 00 66 00 6f 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1) >=8
 
}