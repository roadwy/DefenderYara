
rule Worm_Win32_Qubank_A_bit{
	meta:
		description = "Worm:Win32/Qubank.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 61 63 65 62 6f 6f 6b 20 53 70 72 65 61 64 65 64 20 53 75 63 63 65 73 73 66 75 6c 79 } //1 Facebook Spreaded Successfuly
		$a_01_1 = {51 75 42 61 6e 6b 20 2d 20 49 6e 66 65 63 74 65 64 } //1 QuBank - Infected
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}