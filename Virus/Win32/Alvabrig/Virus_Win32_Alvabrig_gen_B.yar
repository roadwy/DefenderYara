
rule Virus_Win32_Alvabrig_gen_B{
	meta:
		description = "Virus:Win32/Alvabrig.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {78 0c 8b 40 0c 8b 70 1c ad 8b 40 08 eb 09 8b 40 34 8d 40 7c 8b 40 3c 95 e8 00 00 00 00 5e 90 } //1
		$a_01_1 = {ff 75 08 ff 96 88 00 00 00 81 7d f0 54 45 64 69 75 0d } //1
		$a_01_2 = {6c 64 75 70 64 74 2e 6a 70 67 00 4f 70 65 72 61 2f 39 2e 32 30 } //1
		$a_01_3 = {64 74 77 35 64 00 64 74 77 35 64 5c 25 73 5f 25 30 38 64 2e 6c 70 73 74 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}