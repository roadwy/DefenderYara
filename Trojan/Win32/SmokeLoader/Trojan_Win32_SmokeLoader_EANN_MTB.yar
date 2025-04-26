
rule Trojan_Win32_SmokeLoader_EANN_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.EANN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 a4 24 ec 00 00 00 8b 84 24 ec 00 00 00 81 ac 24 ac 01 00 00 ?? ?? ?? ?? 8a 84 0e 3b 2d 0b 00 88 04 39 41 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}