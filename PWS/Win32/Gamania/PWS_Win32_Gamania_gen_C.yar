
rule PWS_Win32_Gamania_gen_C{
	meta:
		description = "PWS:Win32/Gamania.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3 e8 ?? ?? ?? ?? 8b 55 f4 8b c7 e8 ?? ?? ?? ?? ff 45 f8 4e 75 d9 } //8
		$a_01_1 = {8b 4d fc 8a 0c 01 80 f1 86 51 59 88 0c 03 40 4a 75 ee } //5
	condition:
		((#a_03_0  & 1)*8+(#a_01_1  & 1)*5) >=13
 
}