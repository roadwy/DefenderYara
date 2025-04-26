
rule Trojan_Win32_Tesch_A{
	meta:
		description = "Trojan:Win32/Tesch.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 01 8d 46 14 50 8b 46 20 ff 70 14 ff 15 ?? ?? ?? ?? 83 f8 ff 75 ?? ff 76 20 56 } //10
		$a_03_1 = {6a 23 8d 47 04 68 ?? ?? ?? ?? 50 c7 07 32 33 0d 0a e8 ?? ?? ?? ?? 6a 29 66 c7 47 27 0d 0a } //1
		$a_03_2 = {50 c7 06 32 33 0d 0a e8 ?? ?? ?? ?? 83 c4 1c 66 c7 46 27 0d 0a } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=11
 
}