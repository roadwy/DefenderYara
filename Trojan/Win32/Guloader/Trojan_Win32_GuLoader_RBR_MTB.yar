
rule Trojan_Win32_GuLoader_RBR_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {50 6f 6c 79 70 68 79 6c 65 74 69 63 5c 57 61 67 65 73 39 33 } //1 Polyphyletic\Wages93
		$a_81_1 = {6b 6e 73 72 6f 6c 6c 65 64 65 62 61 74 74 65 72 6e 65 20 6a 6f 63 6b 65 79 69 73 6d } //1 knsrolledebatterne jockeyism
		$a_81_2 = {70 75 64 73 65 6e 6d 61 67 65 72 } //1 pudsenmager
		$a_81_3 = {6d 61 6c 6d 73 65 79 20 6d 69 6e 69 6d 75 6d 73 6b 72 61 76 65 74 2e 65 78 65 } //1 malmsey minimumskravet.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}