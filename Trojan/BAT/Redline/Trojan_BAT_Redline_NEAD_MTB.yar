
rule Trojan_BAT_Redline_NEAD_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 7e ?? 00 00 04 11 07 09 08 28 ?? 00 00 06 17 73 ?? 00 00 0a 13 05 7e ?? 00 00 04 11 05 11 06 16 11 06 8e 69 28 ?? 00 00 06 7e ?? 00 00 04 11 05 28 ?? 00 00 06 7e ?? 00 00 04 28 ?? 00 00 06 13 08 7e ?? 00 00 04 11 08 } //10
		$a_01_1 = {52 48 6c 75 59 57 31 70 59 30 52 73 62 45 6c 75 64 6d 39 72 5a 56 52 35 63 47 55 3d } //5 RHluYW1pY0RsbEludm9rZVR5cGU=
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}