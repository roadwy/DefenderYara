
rule Trojan_Win32_BadJoke_EAQL_MTB{
	meta:
		description = "Trojan:Win32/BadJoke.EAQL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {d1 88 94 05 78 56 fc ff 40 3d 80 a9 03 00 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}