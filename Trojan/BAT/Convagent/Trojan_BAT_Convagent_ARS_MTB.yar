
rule Trojan_BAT_Convagent_ARS_MTB{
	meta:
		description = "Trojan:BAT/Convagent.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {2d 08 03 28 ?? ?? ?? ?? 2b 01 16 0a de 05 } //13
		$a_81_1 = {74 65 6d 70 63 61 63 68 65 2e 65 78 65 } //2 tempcache.exe
		$a_81_2 = {53 79 6e 74 65 78 25 32 30 53 70 6f 6f 66 65 72 2e 65 78 65 } //5 Syntex%20Spoofer.exe
	condition:
		((#a_03_0  & 1)*13+(#a_81_1  & 1)*2+(#a_81_2  & 1)*5) >=20
 
}