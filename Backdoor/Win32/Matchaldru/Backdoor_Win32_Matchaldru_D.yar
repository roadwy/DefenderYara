
rule Backdoor_Win32_Matchaldru_D{
	meta:
		description = "Backdoor:Win32/Matchaldru.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {31 34 30 2e 31 31 32 2e 31 39 2e 31 39 35 } //1 140.112.19.195
		$a_01_1 = {73 65 61 72 63 68 35 25 64 } //1 search5%d
		$a_01_2 = {26 68 34 3d } //1 &h4=
		$a_00_3 = {4d 6f 7a 69 6c 6c 61 2f 35 } //1 Mozilla/5
		$a_00_4 = {b2 64 b1 25 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}