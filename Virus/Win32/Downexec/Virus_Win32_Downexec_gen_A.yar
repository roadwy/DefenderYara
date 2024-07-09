
rule Virus_Win32_Downexec_gen_A{
	meta:
		description = "Virus:Win32/Downexec.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 00 00 ff ff 81 38 4d 5a 90 90 00 74 07 2d 00 10 00 00 eb } //1
		$a_03_1 = {81 3f 47 65 74 50 75 ?? 8b df 83 c3 04 81 3b 72 6f 63 41 } //1
		$a_01_2 = {83 c0 01 81 38 8b ff 55 8b 74 05 83 c0 01 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}