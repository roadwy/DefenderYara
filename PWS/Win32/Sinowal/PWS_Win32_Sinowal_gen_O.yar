
rule PWS_Win32_Sinowal_gen_O{
	meta:
		description = "PWS:Win32/Sinowal.gen!O,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 7d f4 03 75 2f 68 } //1
		$a_01_1 = {7b 42 45 45 36 38 36 42 39 2d 34 43 38 34 2d 34 34 38 37 2d 39 44 37 32 2d 39 46 34 30 46 30 35 31 45 39 37 33 7d } //1 {BEE686B9-4C84-4487-9D72-9F40F051E973}
		$a_00_2 = {2d 00 2d 00 63 00 70 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}