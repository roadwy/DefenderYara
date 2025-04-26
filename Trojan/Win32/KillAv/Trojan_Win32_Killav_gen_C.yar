
rule Trojan_Win32_Killav_gen_C{
	meta:
		description = "Trojan:Win32/Killav.gen!C,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {ff ff ff ff 09 00 00 00 64 69 73 61 62 6c 65 46 57 00 00 00 ff ff ff ff 06 00 00 00 6b 69 6c 6c 41 76 00 00 ff ff ff ff 06 00 00 00 64 77 46 69 } //1
		$a_01_1 = {74 72 75 65 00 00 00 00 ff ff ff ff 07 00 00 00 66 77 6b 2e 62 61 74 00 55 8b ec 33 c0 55 68 8d } //1
		$a_01_2 = {0c 00 00 00 4e 41 56 41 50 57 33 32 2e 45 58 45 } //1
		$a_01_3 = {0c 00 00 00 49 43 53 55 50 50 4e 54 2e 45 58 45 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}