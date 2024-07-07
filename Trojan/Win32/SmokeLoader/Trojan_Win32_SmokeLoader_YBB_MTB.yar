
rule Trojan_Win32_SmokeLoader_YBB_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.YBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 65 fc 00 8b 45 10 89 45 fc 8b 45 0c 31 45 fc 8b 45 fc 8b 4d 08 89 01 c9 c2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}