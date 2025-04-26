
rule Backdoor_Linux_Yakuza_YB_MTB{
	meta:
		description = "Backdoor:Linux/Yakuza.YB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {63 64 20 2f 74 6d 70 20 7c 7c 20 63 64 20 2f 76 61 72 2f 72 75 6e 20 7c 7c 20 63 64 20 2f 6d 6e 74 20 7c 7c 20 63 64 20 2f 72 6f 6f 74 20 7c 7c 20 63 64 20 2f 3b 20 77 67 65 74 20 68 74 74 70 [0-02] 3a 2f 2f [0-03] 2e [0-03] 2e [0-03] 2e [0-03] 2f [0-18] 2e 73 68 3b 20 63 68 6d 6f 64 20 37 37 37 20 [0-18] 2e 73 68 3b 20 73 68 20 [0-18] 2e 73 68 3b 20 6b 74 66 74 70 20 [0-03] 2e [0-03] 2e [0-03] 2e [0-03] 20 2d 63 20 67 65 74 20 [0-18] 2e 73 68 3b } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}