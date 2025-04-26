
rule Trojan_Win64_Zenloader_DB_MTB{
	meta:
		description = "Trojan:Win64/Zenloader.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 04 00 00 "
		
	strings :
		$a_81_0 = {53 43 59 54 48 45 20 43 6c 69 65 6e 74 20 48 6f 73 74 } //20 SCYTHE Client Host
		$a_81_1 = {52 65 66 6c 65 63 74 69 76 65 20 4c 6f 61 64 65 72 20 2b 20 44 4c 4c 20 44 69 72 65 63 74 2d 44 6f 77 6e 6c 6f 61 64 20 4c 69 6e 6b 3a } //1 Reflective Loader + DLL Direct-Download Link:
		$a_81_2 = {43 6c 69 65 6e 74 20 73 74 61 72 74 65 64 2e 2e 2e 2e } //1 Client started....
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 20 61 6e 64 20 53 74 61 72 74 } //1 Download and Start
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=23
 
}