
rule Trojan_Win64_SantaStealer_ASA_MTB{
	meta:
		description = "Trojan:Win64/SantaStealer.ASA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 83 7c 24 68 07 4c 8d 44 24 50 48 8d 55 f0 4c 89 74 24 20 4c 0f 47 44 24 50 48 83 7d 08 07 48 0f 47 55 f0 45 33 c9 33 c9 ff 15 } //1
		$a_01_1 = {36 00 32 00 2e 00 36 00 30 00 2e 00 32 00 32 00 36 00 2e 00 39 00 37 00 } //5 62.60.226.97
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5) >=6
 
}