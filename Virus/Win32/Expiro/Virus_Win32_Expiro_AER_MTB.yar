
rule Virus_Win32_Expiro_AER_MTB{
	meta:
		description = "Virus:Win32/Expiro.AER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 45 f0 89 75 f8 50 8d 45 f4 89 75 f4 50 8d 45 f8 c7 45 f0 04 00 00 00 50 56 68 c8 45 40 00 ff 75 fc ff 15 } //2
		$a_01_1 = {56 8d 45 f4 33 f6 50 68 19 00 02 00 56 68 60 43 40 00 68 02 00 00 80 ff 15 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}