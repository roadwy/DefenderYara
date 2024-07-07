
rule Virus_Win32_Alvabrig_gen_D{
	meta:
		description = "Virus:Win32/Alvabrig.gen!D,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5e 8b 5e 24 03 dd 66 8b 0c 4b 8b 5e 1c 03 dd 8b 04 8b 03 c5 5e c3 } //1
		$a_01_1 = {56 8b 75 3c 8b 74 2e 78 03 f5 56 8b 76 20 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}