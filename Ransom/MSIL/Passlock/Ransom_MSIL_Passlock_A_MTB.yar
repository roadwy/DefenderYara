
rule Ransom_MSIL_Passlock_A_MTB{
	meta:
		description = "Ransom:MSIL/Passlock.A!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 50 61 73 73 4c 6f 63 6b 5c 50 61 73 73 4c 6f 63 6b 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 50 61 73 73 4c 6f 63 6b 2e 70 64 62 } //1 \PassLock\PassLock\obj\Release\PassLock.pdb
		$a_01_1 = {53 00 74 00 6f 00 70 00 2c 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 } //1 Stop, your files have been encrypted!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}