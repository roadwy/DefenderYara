
rule Backdoor_Win64_RiverGorilla_D_dha{
	meta:
		description = "Backdoor:Win64/RiverGorilla.D!dha,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {22 6f 62 66 75 73 63 61 74 65 64 22 3a 74 72 75 65 7d 2c 22 5f 6f 62 66 75 73 63 61 74 65 64 22 3a 74 72 75 65 2c 22 63 61 70 61 62 69 6c 69 74 69 65 73 22 3a } //1 "obfuscated":true},"_obfuscated":true,"capabilities":
	condition:
		((#a_01_0  & 1)*1) >=1
 
}