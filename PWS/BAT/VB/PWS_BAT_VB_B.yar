
rule PWS_BAT_VB_B{
	meta:
		description = "PWS:BAT/VB.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 4d 53 4e 37 35 50 61 73 73 77 6f 72 64 73 } //3 getMSN75Passwords
		$a_01_1 = {6b 69 6c 6c 70 72 6f 63 } //1 killproc
		$a_01_2 = {66 69 6c 65 7a 69 6c 6c 61 } //1 filezilla
		$a_01_3 = {41 6e 74 69 53 61 6e 64 62 6f 78 } //2 AntiSandbox
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=4
 
}