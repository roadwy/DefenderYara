
rule Trojan_Win64_Bumblebee_TNK_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.TNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c8 41 01 88 78 01 00 00 8b 05 ?? ?? ?? ?? 41 2b 80 80 01 00 00 48 8b 0d da 04 0a 00 05 5d ee 1a 00 31 81 dc 00 00 00 48 8b 0d c8 04 0a 00 41 8b 80 34 01 00 00 01 81 ?? ?? ?? ?? 41 8b 80 88 00 00 00 48 8b 0d ad 04 0a 00 2d 6e d6 07 00 09 41 18 49 81 fa 08 8c 0d 00 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}