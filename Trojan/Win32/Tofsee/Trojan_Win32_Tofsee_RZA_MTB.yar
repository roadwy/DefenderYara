
rule Trojan_Win32_Tofsee_RZA_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.RZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 b7 59 e7 1f f7 65 90 01 01 8b 45 90 01 01 81 85 90 01 04 f3 ae ac 68 81 6d 90 01 01 b3 30 c7 6b 81 85 90 01 04 21 f4 7c 36 8b 45 90 01 01 30 0c 30 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}