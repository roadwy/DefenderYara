
rule Trojan_Win32_Injector_RPJ_MTB{
	meta:
		description = "Trojan:Win32/Injector.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {21 db 31 0a 90 02 10 81 c2 01 00 00 00 39 fa 75 d4 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}