
rule Worm_Win32_Gamarue_D{
	meta:
		description = "Worm:Win32/Gamarue.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {64 8b 1d 30 00 00 00 8b 5b 0c 8b 5b 0c 83 c3 24 8b 5b 04 } //1
		$a_00_1 = {68 65 78 65 00 68 6f 73 74 2e 68 73 76 63 68 8b dc } //1
		$a_00_2 = {51 51 51 ff 75 bc ff 75 a8 ff 55 c8 } //1
		$a_02_3 = {ac 84 c0 74 09 0c 90 01 01 32 d0 c1 c2 90 01 01 eb fe 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=2
 
}