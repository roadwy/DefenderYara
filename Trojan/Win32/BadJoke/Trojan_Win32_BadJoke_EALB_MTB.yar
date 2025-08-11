
rule Trojan_Win32_BadJoke_EALB_MTB{
	meta:
		description = "Trojan:Win32/BadJoke.EALB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 c2 8d 8d e2 59 f1 ff 8b 45 f4 01 c8 88 10 83 45 f4 01 81 7d f4 00 a6 0e 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}