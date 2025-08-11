
rule Trojan_Win32_Zusy_SCP_MTB{
	meta:
		description = "Trojan:Win32/Zusy.SCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 20 20 20 20 00 50 06 00 00 10 00 00 00 bc 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 f0 c9 30 00 00 60 06 00 00 bc 25 00 00 cc 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}