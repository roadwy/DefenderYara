
rule Trojan_Win32_Jaik_SCPC_MTB{
	meta:
		description = "Trojan:Win32/Jaik.SCPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e0 2e 69 6d 70 6f 72 74 73 00 10 00 00 00 f0 01 00 00 10 00 00 00 f0 01 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 72 73 72 63 00 00 00 00 20 00 00 00 00 02 00 00 20 00 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 74 68 65 6d 69 64 61 00 60 3b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}