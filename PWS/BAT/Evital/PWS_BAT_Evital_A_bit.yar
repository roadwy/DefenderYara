
rule PWS_BAT_Evital_A_bit{
	meta:
		description = "PWS:BAT/Evital.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 76 72 69 61 6c 2e 53 74 65 61 6c 65 72 } //1 Evrial.Stealer
		$a_01_1 = {45 76 72 69 61 6c 2e 48 61 72 64 77 61 72 65 } //1 Evrial.Hardware
		$a_01_2 = {45 76 72 69 61 6c 2e 43 6f 6f 6b 69 65 73 } //1 Evrial.Cookies
		$a_01_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 70 00 72 00 6f 00 6a 00 65 00 63 00 74 00 65 00 76 00 72 00 69 00 61 00 6c 00 2e 00 72 00 75 00 2f 00 } //1 https://projectevrial.ru/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}