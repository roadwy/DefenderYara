
rule PWS_Win32_Sinowal_gen_V{
	meta:
		description = "PWS:Win32/Sinowal.gen!V,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 55 f8 8b 42 3c 8b 4d f8 0f b7 14 01 89 55 bc 8b 45 bc 25 ff 00 00 00 } //1
		$a_01_1 = {8b 45 ec 6b c0 28 8b 4d f0 8b 54 08 08 83 ea 01 52 8b 45 ec 6b c0 28 8b 4d 08 8b 11 8b 4d f0 03 54 08 0c 52 } //1
		$a_01_2 = {8b 55 08 8b 42 10 ff d0 85 c0 75 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}