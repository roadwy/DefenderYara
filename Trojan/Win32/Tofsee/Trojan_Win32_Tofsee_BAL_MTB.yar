
rule Trojan_Win32_Tofsee_BAL_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.BAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {23 03 8d 5b 04 f7 d0 83 e8 ?? 01 f0 8d 40 ff 50 5e 89 01 8d 49 03 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}