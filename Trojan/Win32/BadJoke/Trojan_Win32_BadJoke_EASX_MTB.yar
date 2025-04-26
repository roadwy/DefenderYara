
rule Trojan_Win32_BadJoke_EASX_MTB{
	meta:
		description = "Trojan:Win32/BadJoke.EASX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {88 94 05 f8 f3 fa ff 40 3d fe 0b 05 00 ?? ?? ?? ?? f8 f3 fa ff } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}