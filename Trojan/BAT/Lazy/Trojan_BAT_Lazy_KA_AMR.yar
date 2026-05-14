
rule Trojan_BAT_Lazy_KA_AMR{
	meta:
		description = "Trojan:BAT/Lazy.KA.AMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 09 8f ?? ?? ?? ?? 25 47 03 11 09 03 8e 69 5d 91 61 d2 52 11 09 17 58 13 09 } //5
		$a_81_1 = {55 6e 68 6f 6f 6b 4e 74 64 6c 6c } //1 UnhookNtdll
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*1) >=6
 
}