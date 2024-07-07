
rule Trojan_BAT_AsyncRAT_AX_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 72 90 01 02 00 70 a2 25 17 72 90 01 02 00 70 a2 25 18 72 90 01 02 00 70 a2 25 19 72 90 01 02 00 70 a2 25 1a 72 90 01 02 00 70 a2 25 1b 90 00 } //2
		$a_01_1 = {7b 00 30 00 7d 00 7b 00 31 00 7d 00 3a 00 7b 00 32 00 7d 00 2f 00 7b 00 33 00 7d 00 7b 00 34 00 7d 00 2e 00 } //2 {0}{1}:{2}/{3}{4}.
		$a_01_2 = {2f 00 7b 00 35 00 7d 00 7b 00 36 00 7d 00 2f 00 7b 00 37 00 7d 00 7b 00 38 00 7d 00 7b 00 39 00 7d 00 } //2 /{5}{6}/{7}{8}{9}
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}