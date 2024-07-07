
rule Trojan_Win32_SmokeLoader_FRP_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.FRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 3e 50 31 50 23 50 50 50 08 d9 16 5c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}