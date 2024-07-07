
rule Trojan_Win32_Zenpak_RDP_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 74 42 66 65 6d 61 6c 65 } //1 ttBfemale
		$a_01_1 = {64 73 69 78 74 68 75 6e 64 65 72 } //1 dsixthunder
		$a_01_2 = {64 6f 65 73 6e 2e 74 2e 73 65 74 2c 74 68 69 72 64 } //1 doesn.t.set,third
		$a_01_3 = {69 64 73 74 61 6c 6c 71 56 6d 6e 4e 79 } //1 idstallqVmnNy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}