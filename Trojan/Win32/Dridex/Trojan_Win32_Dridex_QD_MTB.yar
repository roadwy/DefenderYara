
rule Trojan_Win32_Dridex_QD_MTB{
	meta:
		description = "Trojan:Win32/Dridex.QD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_80_0 = {70 75 6c 6c 2e 70 64 62 } //pull.pdb  3
		$a_80_1 = {73 6c 69 70 5c 77 72 6f 6e 67 } //slip\wrong  3
		$a_80_2 = {70 75 6c 6c 2e 64 6c 6c } //pull.dll  3
		$a_80_3 = {43 6c 6f 75 64 73 74 72 65 61 6d } //Cloudstream  3
		$a_80_4 = {48 75 6d 61 6e 73 75 72 66 61 63 65 } //Humansurface  3
		$a_80_5 = {43 72 79 70 74 55 49 57 69 7a 49 6d 70 6f 72 74 } //CryptUIWizImport  3
		$a_80_6 = {43 72 79 70 74 55 49 44 6c 67 56 69 65 77 43 6f 6e 74 65 78 74 } //CryptUIDlgViewContext  3
		$a_80_7 = {43 72 79 70 74 55 49 57 69 7a 46 72 65 65 44 69 67 69 74 61 6c 53 69 67 6e 43 6f 6e 74 65 78 74 } //CryptUIWizFreeDigitalSignContext  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=24
 
}