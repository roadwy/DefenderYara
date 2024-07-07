
rule Trojan_Win32_Oficla_Q{
	meta:
		description = "Trojan:Win32/Oficla.Q,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 01 80 f1 90 01 01 8b 5d 90 01 01 88 0c 03 40 4a 75 ed 90 00 } //2
		$a_01_1 = {62 61 63 6b 75 72 6c 73 3a } //1 backurls:
		$a_01_2 = {72 75 6e 75 72 6c 3a } //1 runurl:
		$a_01_3 = {26 74 6d 3d 31 } //1 &tm=1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}