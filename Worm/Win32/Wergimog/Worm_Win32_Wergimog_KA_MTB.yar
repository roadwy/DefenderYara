
rule Worm_Win32_Wergimog_KA_MTB{
	meta:
		description = "Worm:Win32/Wergimog.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 75 10 33 ff e8 ?? ?? ?? ?? 85 c0 59 76 15 8b 45 10 50 8a 0c 07 30 0c 1e 47 e8 ?? ?? ?? ?? 3b f8 59 72 eb 8a 04 1e f6 d0 88 04 1e 46 3b 75 0c 72 ce } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}