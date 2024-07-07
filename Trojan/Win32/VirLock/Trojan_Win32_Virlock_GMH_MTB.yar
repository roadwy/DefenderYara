
rule Trojan_Win32_Virlock_GMH_MTB{
	meta:
		description = "Trojan:Win32/Virlock.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {40 00 fc 3a 40 00 e8 90 01 04 5c 40 00 10 3b 40 00 04 3b 40 00 04 5d 40 00 98 38 40 00 d4 38 40 00 90 00 } //10
		$a_01_1 = {6f 45 38 4d 6e 4f 74 } //1 oE8MnOt
		$a_01_2 = {50 2e 76 6d 70 30 } //1 P.vmp0
		$a_01_3 = {2e 76 6d 70 31 } //1 .vmp1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}
rule Trojan_Win32_Virlock_GMH_MTB_2{
	meta:
		description = "Trojan:Win32/Virlock.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {00 0c 3b 40 00 10 3b 40 00 04 3b 40 00 7c 38 40 00 98 90 01 04 38 40 00 0a 45 4c 69 73 90 01 01 45 72 72 6f 90 00 } //10
		$a_01_1 = {56 4f 55 37 75 75 78 75 } //1 VOU7uuxu
		$a_01_2 = {7a 41 75 4e 76 69 45 55 } //1 zAuNviEU
		$a_01_3 = {50 2e 76 6d 70 30 } //1 P.vmp0
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}