
rule Backdoor_Win32_Lotok_BT_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 45 ec 8b 75 e8 8b 45 08 8b 4d 10 8b 55 ec 03 c6 6a 00 8a 0c 0a 30 08 ff 15 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}