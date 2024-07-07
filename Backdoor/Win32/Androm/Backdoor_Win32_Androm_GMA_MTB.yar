
rule Backdoor_Win32_Androm_GMA_MTB{
	meta:
		description = "Backdoor:Win32/Androm.GMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 8b f8 66 c7 44 24 18 02 00 ff 15 90 01 04 66 89 44 24 90 01 01 8b 47 0c 6a 10 8b 08 8d 44 24 90 01 01 50 8b 11 8b 4e 08 51 89 54 24 90 01 01 ff 54 24 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}