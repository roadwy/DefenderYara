
rule Backdoor_Win32_ShadowHammer__ShadowHammer{
	meta:
		description = "Backdoor:Win32/ShadowHammer!!ShadowHammer.C!dha,SIGNATURE_TYPE_ARHSTR_EXT,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {da b6 ac e6 c7 90 02 05 c2 5c 37 99 90 00 } //0a 00 
		$a_03_1 = {59 77 ba a3 c7 90 02 05 f8 ce 0c a1 90 00 } //0a 00 
		$a_03_2 = {ad e6 2a 25 c7 90 02 05 7a df 11 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}