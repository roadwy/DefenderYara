
rule Backdoor_Win32_Prometei_GTX_MTB{
	meta:
		description = "Backdoor:Win32/Prometei.GTX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {58 44 45 4c 33 32 2e 44 4c 4c 00 00 57 49 4e 49 4e 45 3c 61 ?? ?? 2c ?? 41 c1 c9 ?? 41 01 c1 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}