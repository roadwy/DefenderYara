
rule Trojan_Win32_Salgorea_SLWO_MTB{
	meta:
		description = "Trojan:Win32/Salgorea.SLWO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {a1 84 c4 46 00 89 35 48 a5 46 00 3b c3 74 07 8b f8 66 39 18 75 02 cc fe 8d 45 fc 50 53 8d 5d f8 33 c9 8b c7 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}