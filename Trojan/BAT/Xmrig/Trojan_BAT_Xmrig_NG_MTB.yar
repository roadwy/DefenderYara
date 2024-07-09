
rule Trojan_BAT_Xmrig_NG_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 0a 00 00 06 75 ?? 00 00 1b 6f ?? 00 00 0a 0a 06 14 28 ?? 00 00 0a 39 ?? 00 00 00 d0 ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 06 14 6f ?? 00 00 0a 75 ?? 00 00 1b } //5
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 33 30 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 WindowsFormsApp30.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}