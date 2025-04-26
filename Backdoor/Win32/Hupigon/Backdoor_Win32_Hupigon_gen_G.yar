
rule Backdoor_Win32_Hupigon_gen_G{
	meta:
		description = "Backdoor:Win32/Hupigon.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 00 8b 00 e8 ?? ?? fc ff 8b 0d ?? ?? 48 00 a1 ?? ?? 48 00 8b 00 8b 15 ?? ?? 47 00 e8 ?? ?? fc ff a1 ?? ?? 48 00 8b 00 e8 ?? ?? fc ff c3 [0-01] 55 8b ec 8b 45 08 48 74 24 48 74 05 48 74 10 eb 5f a1 ?? ?? 48 00 c7 40 04 07 00 00 00 eb 51 90 09 03 00 a1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}