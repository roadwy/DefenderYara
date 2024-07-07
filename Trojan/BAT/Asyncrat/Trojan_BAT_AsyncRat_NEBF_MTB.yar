
rule Trojan_BAT_AsyncRat_NEBF_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {30 62 65 66 39 38 37 64 2d 31 32 38 61 2d 34 32 66 61 2d 39 34 63 37 2d 65 34 61 32 34 62 64 30 63 38 36 61 } //5 0bef987d-128a-42fa-94c7-e4a24bd0c86a
		$a_01_1 = {66 00 6f 00 72 00 65 00 73 00 74 00 6e 00 75 00 72 00 73 00 65 00 } //2 forestnurse
		$a_01_2 = {65 00 6e 00 7a 00 79 00 6d 00 65 00 } //2 enzyme
		$a_01_3 = {49 44 4d 50 41 54 43 48 } //2 IDMPATCH
		$a_01_4 = {70 62 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 pbDebuggerPresent
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=12
 
}