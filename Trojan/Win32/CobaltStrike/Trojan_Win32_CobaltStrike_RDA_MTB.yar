
rule Trojan_Win32_CobaltStrike_RDA_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 10 89 c2 83 e2 07 8a 14 11 8b 4d 08 32 14 01 88 14 06 40 39 c3 } //2
		$a_01_1 = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 6e 65 74 73 76 63 5c } //1 %c%c%c%c%c%c%c%c%cnetsvc\
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}