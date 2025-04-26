
rule Trojan_Win32_Zusy_SCPC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.SCPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 20 20 20 20 00 70 52 00 00 10 00 00 00 ea 1f 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 bc 0a 01 00 00 80 52 00 00 0c 01 00 00 fa 1f 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}