
rule Trojan_BAT_Injector_N_MTB{
	meta:
		description = "Trojan:BAT/Injector.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 6b 64 db 7d 20 2d c7 79 78 61 20 68 35 cf 69 58 61 58 61 ?? ?? ?? ?? ?? 61 61 61 5f 62 0a 02 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}