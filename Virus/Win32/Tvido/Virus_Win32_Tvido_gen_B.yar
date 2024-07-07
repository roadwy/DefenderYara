
rule Virus_Win32_Tvido_gen_B{
	meta:
		description = "Virus:Win32/Tvido.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 7e fc 2e 75 90 01 01 80 7e fd 65 74 06 80 7e fd 45 75 90 01 01 80 7e fe 78 74 06 80 7e fe 58 75 90 01 01 80 7e ff 65 74 06 80 7e ff 45 75 90 01 01 57 ae 75 fd c6 47 ff 5c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}