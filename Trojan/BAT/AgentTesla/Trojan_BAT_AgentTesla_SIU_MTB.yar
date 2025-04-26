
rule Trojan_BAT_AgentTesla_SIU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SIU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {24 30 64 65 63 31 66 38 38 2d 36 37 65 31 2d 34 62 39 63 2d 61 34 63 66 2d 30 36 61 39 31 30 34 31 32 65 64 32 } //1 $0dec1f88-67e1-4b9c-a4cf-06a910412ed2
		$a_81_1 = {68 74 74 70 73 3a 2f 2f 70 6c 61 79 73 74 6f 72 65 6d 65 74 61 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 4c 77 73 67 75 2e 64 61 74 } //1 https://playstoremeta.com/wp-includes/Lwsgu.dat
		$a_81_2 = {46 79 71 63 74 65 72 65 74 2e 65 78 65 } //1 Fyqcteret.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}