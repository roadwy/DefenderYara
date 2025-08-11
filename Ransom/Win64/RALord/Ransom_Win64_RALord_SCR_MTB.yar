
rule Ransom_Win64_RALord_SCR_MTB{
	meta:
		description = "Ransom:Win64/RALord.SCR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_81_0 = {44 45 43 52 59 50 54 49 4f 4e 5f 4b 45 59 2e 74 78 74 } //2 DECRYPTION_KEY.txt
		$a_81_1 = {4d 41 43 48 49 4e 45 5f 49 4e 46 4f 2e 74 78 74 } //1 MACHINE_INFO.txt
		$a_81_2 = {2e 65 6e 63 72 79 70 74 65 64 } //1 .encrypted
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}