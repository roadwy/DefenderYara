
rule PWS_Win32_Sinowal_gen_Z{
	meta:
		description = "PWS:Win32/Sinowal.gen!Z,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 7d f8 1d (73 ?? 0f 83|?? ?? ?? ?? [0)-06] 90 03 05 06 8b 55 ?? ff 75 ?? 5a c1 e2 04 90 03 05 06 8b 45 ?? ff 75 ?? 58 c1 e8 05 } //1
		$a_03_1 = {8b 4d 0c 03 4d ?? 51 ff 55 10 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}