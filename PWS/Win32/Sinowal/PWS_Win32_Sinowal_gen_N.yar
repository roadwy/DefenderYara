
rule PWS_Win32_Sinowal_gen_N{
	meta:
		description = "PWS:Win32/Sinowal.gen!N,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff ff 83 2c 02 ad 75 07 32 c0 e9 90 09 04 00 81 bd } //2
		$a_03_1 = {6a 18 8d 85 ?? ?? ff ff 50 6a 00 6a 00 68 00 00 07 00 8b 4d 08 51 ff 15 } //1
		$a_03_2 = {3d a0 68 06 00 73 0d 68 f4 01 00 00 ff 15 ?? ?? ?? ?? eb c0 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}