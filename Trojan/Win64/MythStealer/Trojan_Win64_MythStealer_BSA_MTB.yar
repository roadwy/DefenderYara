
rule Trojan_Win64_MythStealer_BSA_MTB{
	meta:
		description = "Trojan:Win64/MythStealer.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 79 74 68 2d 4b 65 79 6d 61 69 6e } //4 Myth-Keymain
		$a_01_1 = {6d 79 74 68 2e 63 6f 63 75 6b 70 6f 72 6e 6f 2e 6c 6f 6c 2f 73 63 72 65 65 6e 20 7c 20 56 69 63 74 69 6d } //7 myth.cocukporno.lol/screen | Victim
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*7) >=11
 
}