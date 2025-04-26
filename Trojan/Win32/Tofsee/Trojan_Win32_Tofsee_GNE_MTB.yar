
rule Trojan_Win32_Tofsee_GNE_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 0c 24 ff 0c 24 68 02 10 00 00 ff 0c 24 ff 0c 24 68 8a 06 00 00 ff 0c 24 ff 0c 24 6a 00 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}