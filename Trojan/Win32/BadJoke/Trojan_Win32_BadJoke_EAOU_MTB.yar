
rule Trojan_Win32_BadJoke_EAOU_MTB{
	meta:
		description = "Trojan:Win32/BadJoke.EAOU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 95 5e 56 fc ff 8b 45 f4 01 d0 88 08 83 45 f4 01 81 7d f4 80 a9 03 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}