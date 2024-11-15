
rule Trojan_Win32_Tofsee_KAE_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 db 2b 1e f7 db 83 ee ?? f7 db 8d 5b ?? 83 eb ?? 83 eb ?? 29 d3 29 d2 29 da f7 da } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}