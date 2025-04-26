
rule Trojan_BAT_Xmrig_NIG_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.NIG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 48 00 00 0a 13 33 11 33 73 ?? 00 00 0a 28 ?? 00 00 0a 03 6f ?? 00 00 0a 16 28 ?? 00 00 0a 03 6f ?? 00 00 0a 8e b7 6f ?? 00 00 0a 6f ?? 00 00 0a 11 33 18 6f ?? 00 00 0a 11 33 17 6f ?? 00 00 0a } //5
		$a_01_1 = {57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 20 4d 6f 64 75 6c 65 20 53 65 72 76 69 63 65 } //1 Windows Defender Module Service
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}