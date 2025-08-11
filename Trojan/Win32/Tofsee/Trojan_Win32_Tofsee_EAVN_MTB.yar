
rule Trojan_Win32_Tofsee_EAVN_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.EAVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {c0 e0 06 c0 e3 04 0a f8 0a de 88 45 ff 88 14 31 88 5c 31 01 88 7c 31 02 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}