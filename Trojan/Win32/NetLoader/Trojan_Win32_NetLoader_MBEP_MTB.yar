
rule Trojan_Win32_NetLoader_MBEP_MTB{
	meta:
		description = "Trojan:Win32/NetLoader.MBEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4b 5b 32 0c 1f 89 da d1 ea 83 c3 02 88 0c 17 81 fb ?? ?? ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}