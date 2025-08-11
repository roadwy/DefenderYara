
rule Ransom_Win64_KaWaLocker_A{
	meta:
		description = "Ransom:Win64/KaWaLocker.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6b 00 69 00 6c 00 6c 00 5f 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 00 00 00 00 00 00 00 00 76 00 61 00 6c 00 75 00 65 00 00 00 00 00 00 00 6b 00 69 00 6c 00 6c 00 5f 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 } //1
		$a_01_1 = {4b 61 57 61 4c 6f 63 6b 65 72 } //1 KaWaLocker
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}