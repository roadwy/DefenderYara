
rule Trojan_BAT_AsyncRAT_KAE_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 00 4a 00 51 00 56 00 6d 00 74 00 68 00 55 00 45 00 6c 00 49 00 65 00 } //1 GJQVmthUElIe
		$a_01_1 = {69 00 62 00 65 00 45 00 52 00 4d 00 52 00 45 00 52 00 46 00 76 00 46 00 51 00 } //1 ibeERMRERFvFQ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}