
rule Backdoor_Win32_Androm_GHN_MTB{
	meta:
		description = "Backdoor:Win32/Androm.GHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {56 57 8b 7d 10 33 f6 85 ff 74 0f 0f b6 0c 06 8a 0c 11 88 0c 06 46 3b f7 72 f1 5f 5e 5d c3 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}