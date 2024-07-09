
rule Trojan_BAT_Bepush_I{
	meta:
		description = "Trojan:BAT/Bepush.I,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 00 61 00 62 00 69 00 74 00 90 0a 60 00 65 00 6b 00 [0-06] 61 00 75 00 [0-06] 75 00 70 00 [0-06] 66 00 6f 00 72 00 63 00 65 00 [0-06] 72 00 65 00 67 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}