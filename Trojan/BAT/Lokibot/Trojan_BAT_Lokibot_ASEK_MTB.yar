
rule Trojan_BAT_Lokibot_ASEK_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.ASEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 1f 16 5d 91 13 ?? 07 09 91 11 ?? 61 09 17 58 07 8e 69 5d 13 ?? 07 11 ?? 91 13 ?? 11 ?? 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 ?? 07 09 11 ?? d2 9c 09 17 58 0d 09 07 8e 69 32 } //4
		$a_01_1 = {54 00 59 00 34 00 34 00 42 00 48 00 45 00 37 00 37 00 37 00 57 00 34 00 34 00 47 00 54 00 55 00 34 00 46 00 43 00 41 00 46 00 41 00 } //1 TY44BHE777W44GTU4FCAFA
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}