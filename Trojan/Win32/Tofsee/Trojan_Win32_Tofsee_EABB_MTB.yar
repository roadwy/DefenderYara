
rule Trojan_Win32_Tofsee_EABB_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.EABB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 c0 2b 07 f7 d8 8d 7f 04 f7 d0 f8 83 d0 df 8d 40 ff 29 d0 89 c2 89 06 83 ee fc } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}