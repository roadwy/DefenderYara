
rule Backdoor_Win64_RiverGorilla_E_dha{
	meta:
		description = "Backdoor:Win64/RiverGorilla.E!dha,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {22 6f 62 66 75 73 63 61 74 65 64 22 3a 66 61 6c 73 65 7d 2c 22 5f 6f 62 66 75 73 63 61 74 65 64 22 3a 66 61 6c 73 65 2c 22 63 61 70 61 62 69 6c 69 74 69 65 73 22 3a } //1 "obfuscated":false},"_obfuscated":false,"capabilities":
	condition:
		((#a_01_0  & 1)*1) >=1
 
}