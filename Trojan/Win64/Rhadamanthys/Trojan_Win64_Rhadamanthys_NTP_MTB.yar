
rule Trojan_Win64_Rhadamanthys_NTP_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NTP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 0f af 44 24 30 48 b9 cf f7 53 e3 a5 9b c4 20 48 f7 e9 48 89 d6 48 89 d0 48 c1 e8 3f 48 c1 fe 07 48 01 c6 48 03 74 24 } //1
		$a_01_1 = {48 89 c7 89 f3 d1 eb 48 89 c1 89 da } //2
		$a_01_2 = {56 48 83 ec 20 31 c9 31 d2 45 31 c0 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=5
 
}