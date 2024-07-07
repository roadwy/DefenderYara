
rule Trojan_BAT_Ransom_BSG_MSR{
	meta:
		description = "Trojan:BAT/Ransom.BSG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,2c 01 2c 01 03 00 00 "
		
	strings :
		$a_80_0 = {43 3a 5c 44 65 73 6b 74 6f 70 5c 43 6f 76 2d 4c 6f 63 6b 65 72 5c 43 6f 76 2d 4c 6f 63 6b 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 43 6f 76 2d 4c 6f 63 6b 65 72 2e 70 64 62 } //C:\Desktop\Cov-Locker\Cov-Locker\obj\Release\Cov-Locker.pdb  100
		$a_80_1 = {41 6c 6c 20 79 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 75 73 69 6e 67 20 6d 69 6c 69 74 61 72 79 20 67 72 61 64 65 20 65 6e 63 72 79 70 74 69 6f 6e } //All your personal files have been encrypted using military grade encryption  100
		$a_80_2 = {4f 6f 6f 70 73 2c 20 6c 6f 6f 6b 73 20 6c 69 6b 65 20 79 6f 75 20 67 6f 74 20 74 68 65 20 56 69 72 75 73 21 } //Ooops, looks like you got the Virus!  100
	condition:
		((#a_80_0  & 1)*100+(#a_80_1  & 1)*100+(#a_80_2  & 1)*100) >=300
 
}