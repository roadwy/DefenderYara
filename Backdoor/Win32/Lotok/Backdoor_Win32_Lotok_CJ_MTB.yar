
rule Backdoor_Win32_Lotok_CJ_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.CJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 99 f7 fb 8b 45 10 57 6a 01 6a 01 8a 0c 02 30 4d 0b 8d 55 0b 52 e8 90 02 04 83 c4 10 ff 45 fc 56 e8 90 02 04 83 c4 04 85 c0 74 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}