
rule Worm_Win64_Boychi_A_sys{
	meta:
		description = "Worm:Win64/Boychi.A!sys,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 4d 00 53 00 48 00 34 00 44 00 45 00 56 00 31 00 } //1 \DosDevices\MSH4DEV1
		$a_01_1 = {40 53 48 83 ec 30 ba 40 00 00 00 33 c9 41 b8 44 52 4d 4d } //2
		$a_01_2 = {66 f2 af 49 8b d0 48 f7 d1 48 ff c9 0f b7 c1 66 03 c0 66 89 44 24 30 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=5
 
}