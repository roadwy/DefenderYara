
rule Trojan_Win32_Tofsee_AB_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f8 00 0f 85 b5 7c 00 00 ?? b8 7e a5 40 00 68 7e a5 40 00 8d 05 00 00 00 00 50 8d 05 00 00 10 00 50 e8 9b 7c 00 00 83 f8 00 0f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}