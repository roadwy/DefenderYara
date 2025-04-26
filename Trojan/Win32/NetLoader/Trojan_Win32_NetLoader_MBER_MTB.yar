
rule Trojan_Win32_NetLoader_MBER_MTB{
	meta:
		description = "Trojan:Win32/NetLoader.MBER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 4c 1f 01 32 0c 1f 89 da d1 ea 83 c3 02 88 0c 17 81 fb ?? ?? ?? ?? 60 89 fa 89 d1 61 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}