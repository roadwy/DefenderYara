
rule Virus_Win32_Expiro_MJ_bit{
	meta:
		description = "Virus:Win32/Expiro.MJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 56 30 8b 0a 81 e1 df 00 df 00 8b 52 0b 03 d1 c1 ea 02 81 ea d2 4c 91 0c } //1
		$a_03_1 = {8b 0f 85 f2 81 f1 90 01 04 39 ce 89 0e 8d 0f 81 c6 04 00 00 00 81 c7 04 00 00 00 83 ea 04 85 d2 75 90 00 } //1
		$a_01_2 = {89 c7 8b 75 9c 8b 5d 90 b9 ff 00 00 00 99 f7 f9 88 14 33 ff 45 9c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}