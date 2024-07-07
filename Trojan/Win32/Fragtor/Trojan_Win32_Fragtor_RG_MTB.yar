
rule Trojan_Win32_Fragtor_RG_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {34 a6 4f 87 af 7a ea dc 60 43 40 1f 33 3c 3b 3a 0c b8 f5 9b ea ec 45 0c eb 59 3a f2 34 58 8b fe } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}