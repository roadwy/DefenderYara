
rule Trojan_Win32_RiseProStealer_RHF_MTB{
	meta:
		description = "Trojan:Win32/RiseProStealer.RHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_03_0 = {40 00 00 e0 2e 72 73 72 63 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 74 61 67 67 61 6e 74 } //2
		$a_03_1 = {e9 00 20 00 00 00 90 09 0a 00 eb 08 } //2
		$a_03_2 = {50 45 00 00 4c 01 07 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0e 22 00 ?? 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 00 00 10 00 00 00 ?? 10 00 } //2
		$a_02_3 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 ?? ?? ?? ?? 41 00 75 00 33 00 } //1
		$a_02_4 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 ?? ?? ?? ?? 41 00 79 00 33 00 49 00 6e 00 66 00 6f 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1) >=8
 
}