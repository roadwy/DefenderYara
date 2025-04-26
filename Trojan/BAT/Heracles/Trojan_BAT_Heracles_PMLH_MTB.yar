
rule Trojan_BAT_Heracles_PMLH_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PMLH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 2c 67 00 0f 01 28 ?? 00 00 0a 1f 10 62 0f 01 28 ?? 00 00 0a 1e 62 60 0f 01 28 ?? 00 00 0a 60 0b 07 20 ?? ?? ?? ?? 61 0c 08 1f 10 63 20 ff 00 00 00 5f d2 0d } //9
		$a_01_1 = {4c 00 6f 00 61 00 64 00 00 21 47 00 65 00 74 00 45 00 78 00 70 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 70 00 65 00 73 } //1
	condition:
		((#a_03_0  & 1)*9+(#a_01_1  & 1)*1) >=10
 
}