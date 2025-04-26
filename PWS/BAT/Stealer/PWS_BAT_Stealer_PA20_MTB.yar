
rule PWS_BAT_Stealer_PA20_MTB{
	meta:
		description = "PWS:BAT/Stealer.PA20!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 62 6b 70 2e 6d 79 66 74 70 2e 6f 72 67 2f 63 6f 6d 70 72 61 73 2f 67 61 74 65 2e 70 68 70 } //http://bkp.myftp.org/compras/gate.php  1
		$a_80_1 = {5c 43 68 72 6f 6d 65 50 61 73 73 77 6f 72 64 73 2e 74 78 74 } //\ChromePasswords.txt  1
		$a_80_2 = {5c 49 6e 74 65 72 6e 65 74 45 78 70 6c 6f 72 65 72 5c 49 45 50 61 73 73 77 6f 72 64 73 2e 74 78 74 } //\InternetExplorer\IEPasswords.txt  1
		$a_80_3 = {57 69 6e 64 6f 77 73 20 57 65 62 20 50 61 73 73 77 6f 72 64 20 43 72 65 64 65 6e 74 69 61 6c } //Windows Web Password Credential  1
		$a_80_4 = {73 74 65 61 6c 65 72 2e 70 64 62 } //stealer.pdb  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}