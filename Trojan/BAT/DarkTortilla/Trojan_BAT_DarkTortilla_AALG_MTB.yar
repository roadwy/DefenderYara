
rule Trojan_BAT_DarkTortilla_AALG_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AALG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 13 18 8d ?? 00 00 01 25 16 11 1d 8c ?? 00 00 01 a2 25 17 28 ?? 01 00 06 11 1d 18 d6 5d 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 11 1d 17 d6 13 1d 11 1d 1f 0a 31 ca } //5
		$a_01_1 = {71 00 71 00 61 00 7a 00 73 00 67 00 67 00 66 00 67 00 66 00 64 00 64 00 64 00 67 00 67 00 64 00 64 00 67 00 73 00 64 00 77 00 } //1 qqazsggfgfdddggddgsdw
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}