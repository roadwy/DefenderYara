
rule Trojan_Win32_SmokeLoader_W_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.W!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 45 f0 8b 45 f0 89 45 ec 8b 55 f8 8b 4d f4 d3 ea 03 d3 8b 45 ec 31 45 fc 31 55 fc 2b 7d fc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}