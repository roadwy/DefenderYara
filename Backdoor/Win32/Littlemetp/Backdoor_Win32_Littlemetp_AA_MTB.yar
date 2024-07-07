
rule Backdoor_Win32_Littlemetp_AA_MTB{
	meta:
		description = "Backdoor:Win32/Littlemetp.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 90 01 01 8b 45 90 01 01 8b 55 90 01 01 01 02 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 03 45 90 01 01 89 45 90 01 01 6a 00 e8 90 02 04 8b 5d 90 01 01 2b d8 6a 00 e8 90 02 04 2b d8 8b 45 90 01 01 31 18 83 45 90 02 02 83 45 90 02 02 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}