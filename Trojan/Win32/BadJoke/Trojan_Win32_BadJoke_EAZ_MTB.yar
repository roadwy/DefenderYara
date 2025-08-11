
rule Trojan_Win32_BadJoke_EAZ_MTB{
	meta:
		description = "Trojan:Win32/BadJoke.EAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 d0 2a d0 88 90 80 f8 42 00 40 3d 05 52 00 00 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}