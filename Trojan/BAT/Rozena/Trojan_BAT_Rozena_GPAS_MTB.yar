
rule Trojan_BAT_Rozena_GPAS_MTB{
	meta:
		description = "Trojan:BAT/Rozena.GPAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 00 6d 73 63 6f 72 6c 69 62 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //8 楖瑲慵䅬汬捯硅畎慭洀捳牯楬b楖瑲慵䅬汬捯
	condition:
		((#a_01_0  & 1)*8) >=8
 
}