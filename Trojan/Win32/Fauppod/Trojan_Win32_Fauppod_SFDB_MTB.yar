
rule Trojan_Win32_Fauppod_SFDB_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.SFDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_81_0 = {53 6b 65 69 4f 65 69 74 78 6e 65 73 65 } //2 SkeiOeitxnese
		$a_01_1 = {74 65 64 73 72 74 61 6d 6f 6c 33 30 2e 64 6c 6c } //1 tedsrtamol30.dll
	condition:
		((#a_81_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}