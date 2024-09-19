
rule Trojan_Win32_Blackmoon_NB_MTB{
	meta:
		description = "Trojan:Win32/Blackmoon.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {34 37 2e 39 39 2e 32 31 34 2e 32 31 34 } //2 47.99.214.214
		$a_01_1 = {6f 74 61 6c 6d 2e 74 78 74 } //2 otalm.txt
		$a_01_2 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 20 45 72 72 6f 72 } //2 BlackMoon RunTime Error
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}