
rule Trojan_Win32_BadJoke_EAGM_MTB{
	meta:
		description = "Trojan:Win32/BadJoke.EAGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {88 84 0d f8 f3 fa ff 41 81 f9 fe 0b 05 00 ?? ?? ?? ?? f8 f3 fa ff } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}