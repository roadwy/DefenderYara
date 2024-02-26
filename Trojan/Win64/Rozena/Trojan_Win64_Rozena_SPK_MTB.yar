
rule Trojan_Win64_Rozena_SPK_MTB{
	meta:
		description = "Trojan:Win64/Rozena.SPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {f3 0f 6f 40 e0 66 0f ef c2 f3 0f 7f 40 e0 f3 0f 6f 40 f0 66 0f 6f ca 66 0f ef c8 f3 0f 7f 48 f0 f3 0f 6f 00 66 0f 6f ca 66 0f ef c8 f3 0f 7f 08 f3 0f 6f 40 10 66 0f ef c2 f3 0f 7f 40 10 48 83 c1 40 48 8d 40 40 48 3b ca 7c b5 } //00 00 
	condition:
		any of ($a_*)
 
}