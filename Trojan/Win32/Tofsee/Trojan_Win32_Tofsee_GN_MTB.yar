
rule Trojan_Win32_Tofsee_GN_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b7 59 e7 1f f7 a4 24 [0-10] 8b 84 24 [0-10] 81 84 24 [0-10] 81 6c 24 [0-30] 30 0c 06 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}