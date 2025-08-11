
rule Trojan_Win32_Tofsee_BAK_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.BAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 f8 29 ff 29 c7 f7 df 6a 00 8f 01 01 41 00 83 e9 fc 83 c3 fc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}