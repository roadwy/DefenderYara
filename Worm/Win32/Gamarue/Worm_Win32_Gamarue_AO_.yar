
rule Worm_Win32_Gamarue_AO_{
	meta:
		description = "Worm:Win32/Gamarue.AO!!Gamarue.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 0c 6a ff c7 45 ec 07 80 00 00 ff 50 18 e8 ?? ?? ?? ?? 8d 98 ?? ?? ?? ?? ff 73 10 8b 45 0c 8d 73 ?? 56 33 ff 57 89 5d d8 ff 50 10 } //1
		$a_01_1 = {0f be c9 33 c8 c1 c1 09 8b c1 42 8a 0a 84 c9 75 ef } //5
		$a_01_2 = {ac 8a c8 3c 0f 74 0f 66 81 7e ff cd 20 75 0a 46 ad } //5
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=11
 
}