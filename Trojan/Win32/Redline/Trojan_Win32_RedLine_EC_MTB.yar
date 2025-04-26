
rule Trojan_Win32_RedLine_EC_MTB{
	meta:
		description = "Trojan:Win32/RedLine.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f be 04 0a c1 e0 10 33 45 f8 89 45 f8 b9 01 00 00 00 c1 e1 00 8b 55 e0 0f be 04 0a c1 e0 08 33 45 f8 89 45 f8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_RedLine_EC_MTB_2{
	meta:
		description = "Trojan:Win32/RedLine.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {44 00 61 00 67 00 67 00 65 00 72 00 68 00 61 00 73 00 68 00 69 00 6d 00 6f 00 74 00 6f 00 20 00 38 00 38 00 38 00 } //1 Daggerhashimoto 888
		$a_01_1 = {65 00 78 00 74 00 65 00 6e 00 64 00 6b 00 65 00 79 00 2e 00 64 00 61 00 74 00 } //1 extendkey.dat
		$a_01_2 = {72 00 65 00 67 00 6b 00 65 00 79 00 2e 00 64 00 61 00 74 00 } //1 regkey.dat
		$a_01_3 = {40 2e 76 6d 5f 73 65 63 } //1 @.vm_sec
		$a_01_4 = {2e 77 69 6e 6c 69 63 65 } //1 .winlice
		$a_01_5 = {2e 62 6f 6f 74 } //1 .boot
		$a_01_6 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //1 CreateProcessA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}