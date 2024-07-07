
rule PWS_BAT_Costealer_A_bit{
	meta:
		description = "PWS:BAT/Costealer.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 00 61 00 67 00 64 00 6e 00 73 00 2e 00 63 00 6f 00 6d 00 90 02 2f 73 00 74 00 61 00 72 00 74 00 2e 00 70 00 68 00 70 00 90 00 } //10
		$a_01_1 = {77 00 61 00 6c 00 6c 00 65 00 74 00 2e 00 64 00 61 00 74 00 } //1 wallet.dat
		$a_01_2 = {75 00 70 00 70 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 upper.exe
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}