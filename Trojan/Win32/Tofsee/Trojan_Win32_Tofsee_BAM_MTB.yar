
rule Trojan_Win32_Tofsee_BAM_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.BAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 36 58 f8 83 d6 04 f7 d0 f8 83 d8 26 f8 83 d0 ff 29 d0 6a ff 5a 21 c2 89 01 83 c1 04 f8 83 df 04 83 ff 00 75 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}