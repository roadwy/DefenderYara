
rule Trojan_Win32_Injector_C_MTB{
	meta:
		description = "Trojan:Win32/Injector.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {85 c0 39 db 85 c0 39 db ff 34 0f 85 c0 d9 d0 85 c0 31 34 24 85 c0 39 db 85 c0 8f 04 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}