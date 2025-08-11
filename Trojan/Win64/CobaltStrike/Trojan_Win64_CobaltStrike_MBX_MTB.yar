
rule Trojan_Win64_CobaltStrike_MBX_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 0e 48 01 d9 48 8d 54 24 2c 49 89 f8 e8 d9 6b 00 00 48 01 fb 48 89 5e 10 48 83 c4 30 } //1
		$a_01_1 = {4c bc 00 00 00 30 02 00 00 be 00 00 00 18 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 64 61 74 61 00 00 00 f8 02 00 00 00 f0 02 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}