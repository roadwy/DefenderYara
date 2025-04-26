
rule Trojan_Win32_Tofsee_BAF_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 02 83 c2 04 f7 d8 83 c0 da 83 e8 02 83 e8 ff 29 f0 8d 30 6a 00 8f 01 01 01 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}