
rule Trojan_Win32_BadJoke_EAMG_MTB{
	meta:
		description = "Trojan:Win32/BadJoke.EAMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {22 c2 88 84 0d 78 56 fc ff 41 81 f9 80 a9 03 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}