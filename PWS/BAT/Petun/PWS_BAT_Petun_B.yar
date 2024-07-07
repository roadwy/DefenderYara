
rule PWS_BAT_Petun_B{
	meta:
		description = "PWS:BAT/Petun.B,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 55 73 65 72 73 5c 41 64 72 69 61 6e 5c 44 65 73 6b 74 6f 70 5c 4e 45 57 20 4e 30 24 63 72 79 70 74 65 72 5c } //1 \Users\Adrian\Desktop\NEW N0$crypter\
		$a_01_1 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 5c 00 43 00 72 00 65 00 64 00 65 00 6e 00 74 00 69 00 61 00 6c 00 73 00 } //1 Microsoft\Protect\Credentials
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}