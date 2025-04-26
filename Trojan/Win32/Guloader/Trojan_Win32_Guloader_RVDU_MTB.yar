
rule Trojan_Win32_Guloader_RVDU_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RVDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 73 70 6f 74 6d 61 72 6b 65 64 65 74 73 5c 6c 69 70 6f 69 64 69 63 2e 69 6e 69 } //1 \spotmarkedets\lipoidic.ini
		$a_81_1 = {5c 44 6f 65 64 5c 62 61 73 69 6c 69 73 6b 65 6e 73 } //1 \Doed\basiliskens
		$a_81_2 = {6b 72 61 6d 65 72 69 61 63 65 6f 75 73 20 68 61 6e 6e 61 73 20 67 65 6f 73 79 6e 63 6c 69 6e 61 6c } //1 krameriaceous hannas geosynclinal
		$a_81_3 = {76 69 64 65 6f 70 6c 61 64 65 72 20 66 72 70 65 72 73 70 65 6b 74 69 76 65 72 73 } //1 videoplader frperspektivers
		$a_81_4 = {76 65 73 74 65 75 72 6f 70 65 72 2e 65 78 65 } //1 vesteuroper.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}