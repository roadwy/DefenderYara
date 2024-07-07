
rule Trojan_Win32_DelfInject_AB_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 d4 31 18 83 45 ec 04 83 45 d4 04 8b 45 ec } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}