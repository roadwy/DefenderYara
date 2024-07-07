
rule Trojan_Win32_Lazy_AMAB_MTB{
	meta:
		description = "Trojan:Win32/Lazy.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 6e 6a 62 79 76 74 4b 6d 69 6e 75 62 79 } //1 InjbyvtKminuby
		$a_01_1 = {4f 6d 69 6e 75 62 48 76 79 74 63 } //1 OminubHvytc
		$a_01_2 = {55 74 76 79 62 52 74 76 79 62 } //1 UtvybRtvyb
		$a_01_3 = {55 72 63 74 76 4b 74 63 76 79 62 } //1 UrctvKtcvyb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}