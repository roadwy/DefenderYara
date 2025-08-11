
rule Trojan_Win32_Neoreblamy_NIL_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NIL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 40 89 45 f4 83 7d f4 ?? 7d 0d 8b 45 f4 } //1
		$a_01_1 = {6a 04 58 c1 e0 00 8b 44 05 c8 40 6a 04 59 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}