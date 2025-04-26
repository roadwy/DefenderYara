
rule Worm_Win32_Flukan_A{
	meta:
		description = "Worm:Win32/Flukan.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 00 69 00 72 00 75 00 73 00 5c 00 46 00 6c 00 75 00 2d 00 49 00 6b 00 61 00 6e 00 5c 00 46 00 6c 00 75 00 5f 00 49 00 6b 00 61 00 6e 00 2e 00 76 00 62 00 70 00 } //1 Virus\Flu-Ikan\Flu_Ikan.vbp
		$a_01_1 = {6e 00 31 00 3d 00 2f 00 6e 00 69 00 63 00 6b 00 20 00 2f 00 72 00 65 00 6d 00 6f 00 74 00 65 00 20 00 6f 00 6e 00 } //1 n1=/nick /remote on
		$a_01_2 = {52 00 61 00 76 00 54 00 69 00 6d 00 65 00 58 00 50 00 } //1 RavTimeXP
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}