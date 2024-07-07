
rule Virus_Win32_Otwycal_gen_B{
	meta:
		description = "Virus:Win32/Otwycal.gen!B,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 2c 01 00 00 ff 75 38 ff 55 10 6a 00 68 2e 65 78 74 68 64 6f 77 73 68 5c 77 69 6e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}